from flask import Flask, render_template, request, redirect, session, jsonify, abort
from pymongo import MongoClient
import certifi
import bcrypt
import os
from dotenv import load_dotenv
import requests
import time
import secrets
import re
from bson.objectid import ObjectId

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("FLASK_ENV") == "production"
TWITCH_CLIENT_ID = os.getenv("TWITCH_CLIENT_ID", "").strip()
TWITCH_CLIENT_SECRET = os.getenv("TWITCH_CLIENT_SECRET", "").strip()

MONGODB_URI = os.getenv("MONGODB_URI")
if not MONGODB_URI:
    raise ValueError("Missing MONGODB_URI. Put it in your .env file.")

client = MongoClient(MONGODB_URI, tlsCAFile=certifi.where())

db = client["TeamSwipe"]
collection = db["users"]
posts_collection = db["posts"]
games_collection = db["games"]
invite_requests_collection = db["invite_requests"]
swipe_actions_collection = db["swipe_actions"]

igdb_token_cache = {
    "access_token": None,
    "expires_at": 0,
}

RATE_LIMIT_BUCKETS = {}
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_RULES = {
    "login": 10,
    "register": 5,
    "create_post": 10,
    "swipe": 60,
    "invite_decision": 30,
    "profile_update": 20,
}


def current_user_email():
    return session.get("user_email")


def current_user_doc():
    user_email = current_user_email()
    if not user_email:
        return None
    return collection.find_one({"email": user_email})


def ensure_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": ensure_csrf_token()}


def validate_csrf():
    session_token = session.get("csrf_token", "")
    request_token = (
        request.form.get("csrf_token", "").strip()
        or request.headers.get("X-CSRF-Token", "").strip()
    )
    if not session_token or not request_token or not secrets.compare_digest(session_token, request_token):
        abort(403)


def client_identifier():
    return current_user_email() or request.remote_addr or "anonymous"


def enforce_rate_limit(bucket_name):
    limit = RATE_LIMIT_RULES.get(bucket_name)
    if not limit:
        return

    now = time.time()
    key = f"{bucket_name}:{client_identifier()}"
    window_start = now - RATE_LIMIT_WINDOW_SECONDS
    timestamps = [ts for ts in RATE_LIMIT_BUCKETS.get(key, []) if ts > window_start]

    if len(timestamps) >= limit:
        abort(429)

    timestamps.append(now)
    RATE_LIMIT_BUCKETS[key] = timestamps


def validate_text_field(value, field_name, max_length, required=True, pattern=None):
    cleaned = value.strip()
    if required and not cleaned:
        raise ValueError(f"{field_name} is required.")
    if len(cleaned) > max_length:
        raise ValueError(f"{field_name} must be {max_length} characters or fewer.")
    if cleaned and pattern and not re.fullmatch(pattern, cleaned):
        raise ValueError(f"{field_name} contains unsupported characters.")
    return cleaned


def serialize_post(post, viewer_email=None):
    serialized = {
        "_id": str(post["_id"]),
        "user_email": post.get("user_email", ""),
        "game_name": post.get("game_name", ""),
        "post_name": post.get("post_name", ""),
        "description": post.get("description", ""),
        "platform_name": post.get("platform_name", ""),
        "tags": [tag for tag in post.get("tags", []) if tag],
        "image_url": post.get("image_url", "/static/default-game.jpg"),
        "is_own_post": bool(viewer_email and post.get("user_email") == viewer_email),
    }
    return serialized


def build_browse_query(game_filter, tag_filter):
    filters = []

    if game_filter:
        filters.append({
            "game_name": {"$regex": re.escape(game_filter), "$options": "i"}
        })

    if tag_filter:
        filters.append({
            "tags": {"$elemMatch": {"$regex": re.escape(tag_filter), "$options": "i"}}
        })

    if not filters:
        return {}

    return {"$and": filters}


def get_swipe_candidate_ids(user_email):
    if not user_email:
        return set()

    acted_ids = {
        action["post_id"]
        for action in swipe_actions_collection.find(
            {"user_email": user_email},
            {"_id": 0, "post_id": 1},
        )
        if action.get("post_id")
    }

    acted_ids.update(
        {
            str(invite["post_id"])
            for invite in invite_requests_collection.find(
                {"requester_email": user_email},
                {"_id": 0, "post_id": 1},
            )
            if invite.get("post_id")
        }
    )

    return acted_ids


def build_swipe_posts(game_filter, tag_filter, viewer_email):
    base_query = build_browse_query(game_filter, tag_filter)
    if viewer_email:
        base_query.setdefault("$and", []).append({"user_email": {"$ne": viewer_email}})

    acted_ids = get_swipe_candidate_ids(viewer_email)
    if acted_ids:
        base_query.setdefault("$and", []).append(
            {"_id": {"$nin": [ObjectId(post_id) for post_id in acted_ids if ObjectId.is_valid(post_id)]}}
        )

    posts = list(posts_collection.find(base_query).sort("_id", -1))
    return [serialize_post(post, viewer_email) for post in posts]


def get_igdb_access_token():
    now = time.time()

    if igdb_token_cache["access_token"] and now < igdb_token_cache["expires_at"]:
        return igdb_token_cache["access_token"]

    response = requests.post(
        "https://id.twitch.tv/oauth2/token",
        data={
            "client_id": TWITCH_CLIENT_ID,
            "client_secret": TWITCH_CLIENT_SECRET,
            "grant_type": "client_credentials",
        },
        timeout=20,
    )
    response.raise_for_status()

    data = response.json()
    igdb_token_cache["access_token"] = data["access_token"]
    igdb_token_cache["expires_at"] = now + data["expires_in"] - 60
    return igdb_token_cache["access_token"]


def get_game_cover_from_igdb(game_name: str) -> str | None:
    normalized = game_name.strip().lower()
    if not normalized:
        return None

    access_token = get_igdb_access_token()

    headers = {
        "Client-ID": TWITCH_CLIENT_ID,
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    search_body = f'''
    search "{game_name}";
    fields id,name;
    limit 10;
    '''

    search_response = requests.post(
        "https://api.igdb.com/v4/games",
        headers=headers,
        data=search_body.encode("utf-8"),
        timeout=20,
    )
    search_response.raise_for_status()

    games = search_response.json()
    if not games:
        return None

    exact_match = next(
        (game for game in games if game.get("name", "").strip().lower() == normalized),
        None,
    )

    startswith_match = next(
        (game for game in games if game.get("name", "").strip().lower().startswith(normalized)),
        None,
    )

    chosen_game = exact_match or startswith_match or games[0]
    game_id = chosen_game["id"]

    covers_body = f'''
    fields game,image_id,url,width,height;
    where game = {game_id};
    limit 1;
    '''

    covers_response = requests.post(
        "https://api.igdb.com/v4/covers",
        headers=headers,
        data=covers_body.encode("utf-8"),
        timeout=20,
    )
    covers_response.raise_for_status()

    covers = covers_response.json()
    if not covers:
        return None

    cover = covers[0]

    cover_url = cover.get("url")
    if cover_url:
        if cover_url.startswith("//"):
            cover_url = "https:" + cover_url
        return cover_url.replace("t_thumb", "t_cover_big")

    image_id = cover.get("image_id")
    if image_id:
        return f"https://images.igdb.com/igdb/image/upload/t_cover_big/{image_id}.jpg"

    return None


def get_game_cover(game_name):
    normalized_name = game_name.strip()
    if not normalized_name:
        return "/static/default-game.jpg"

    game_doc = games_collection.find_one(
        {"name": {"$regex": f"^{re.escape(normalized_name)}$", "$options": "i"}},
        {"_id": 0, "name": 1, "image_url": 1},
    )

    if game_doc and game_doc.get("image_url"):
        return game_doc["image_url"]

    image_url = get_game_cover_from_igdb(normalized_name)

    if not image_url:
        return "/static/default-game.jpg"

    games_collection.update_one(
        {"name": {"$regex": f"^{re.escape(normalized_name)}$", "$options": "i"}},
        {"$set": {"name": normalized_name, "image_url": image_url}},
        upsert=True,
    )

    return image_url


@app.route("/")
def home():
    try:
        games = list(games_collection.find({}, {"_id": 0, "name": 1, "image_url": 1}))
    except Exception:
        games = []

    return render_template("index.html", games=games)


@app.route("/browse")
def browse():
    user_email = current_user_email()
    game_filter = request.args.get("game", "").strip()
    tag_filter = request.args.get("tag", "").strip()
    has_filters = bool(game_filter or tag_filter)
    mode = request.args.get("mode", "").strip().lower()

    if mode not in {"grid", "swipe"}:
        mode = "swipe" if has_filters else "grid"

    posts = [
        serialize_post(post, user_email)
        for post in posts_collection.find(build_browse_query(game_filter, tag_filter)).sort("_id", -1)
    ]

    swipe_posts = build_swipe_posts(game_filter, tag_filter, user_email) if has_filters and user_email else []
    swipe_state = "available"
    if has_filters and mode == "swipe":
        if not user_email:
            swipe_state = "login_required"
        elif swipe_posts:
            swipe_state = "available"
        elif posts:
            swipe_state = "exhausted"
        else:
            swipe_state = "no_matches"

    return render_template(
        "browse.html",
        posts=posts,
        swipe_posts=swipe_posts,
        game_filter=game_filter,
        tag_filter=tag_filter,
        has_filters=has_filters,
        mode=mode,
        is_logged_in=bool(user_email),
        swipe_state=swipe_state,
    )


@app.route("/create")
def create():
    if not current_user_email():
        return redirect("/login")
    return render_template("create.html")


@app.route("/create-post", methods=["POST"])
def create_post():
    validate_csrf()
    enforce_rate_limit("create_post")
    user_email = current_user_email()
    if not user_email:
        return redirect("/login")

    try:
        game_name = validate_text_field(request.form["game_name"], "Game name", 60)
        post_name = validate_text_field(request.form["post_name"], "Post name", 52)
        description = validate_text_field(request.form.get("description", ""), "Description", 400, required=False)
        platform_name = validate_text_field(request.form["platform_name"], "Platform name", 40)
        tag1 = validate_text_field(request.form.get("tag_1", ""), "Tag 1", 24, required=False)
        tag2 = validate_text_field(request.form.get("tag_2", ""), "Tag 2", 24, required=False)
        tag3 = validate_text_field(request.form.get("tag_3", ""), "Tag 3", 24, required=False)
    except ValueError as exc:
        return str(exc), 400

    image_url = get_game_cover(game_name)

    posts_collection.insert_one(
        {
            "user_email": user_email,
            "game_name": game_name,
            "post_name": post_name,
            "description": description,
            "platform_name": platform_name,
            "tags": [tag1, tag2, tag3],
            "image_url": image_url or "/static/default-game.jpg",
        }
    )

    return redirect("/browse")


@app.route("/browse/swipe-action", methods=["POST"])
def browse_swipe_action():
    validate_csrf()
    enforce_rate_limit("swipe")
    user_email = current_user_email()
    if not user_email:
        return jsonify({"error": "Please log in to use swipe mode."}), 401

    payload = request.get_json(silent=True) or {}
    post_id = payload.get("post_id", "").strip()
    action = payload.get("action", "").strip().lower()

    if not ObjectId.is_valid(post_id):
        return jsonify({"error": "Invalid post."}), 400

    if action not in {"left", "right"}:
        return jsonify({"error": "Invalid action."}), 400

    post = posts_collection.find_one({"_id": ObjectId(post_id)})
    if not post:
        return jsonify({"error": "Post not found."}), 404

    if post.get("user_email") == user_email:
        return jsonify({"error": "You cannot swipe on your own post."}), 400

    swipe_actions_collection.update_one(
        {"user_email": user_email, "post_id": post_id},
        {"$set": {"action": action, "updated_at": time.time()}},
        upsert=True,
    )

    if action == "right":
        requester = current_user_doc() or {}
        existing_request = invite_requests_collection.find_one(
            {
                "post_id": post_id,
                "requester_email": user_email,
                "status": {"$in": ["pending", "approved"]},
            }
        )

        if not existing_request:
            invite_requests_collection.insert_one(
                {
                    "post_id": post_id,
                    "post_name": post.get("post_name", ""),
                    "game_name": post.get("game_name", ""),
                    "post_owner_email": post.get("user_email", ""),
                    "requester_email": user_email,
                    "status": "pending",
                    "created_at": time.time(),
                    "updated_at": time.time(),
                    "response_message": "",
                    "requester_discord_username": requester.get("discord_username", "").strip(),
                    "owner_discord_username": "",
                }
            )

    return jsonify({"ok": True})


@app.route("/invite/<invite_id>/<decision>", methods=["POST"])
def invite_decision(invite_id, decision):
    validate_csrf()
    enforce_rate_limit("invite_decision")
    owner_email = current_user_email()
    if not owner_email:
        return redirect("/login")

    if decision not in {"approve", "deny"}:
        return redirect("/notification")

    if not ObjectId.is_valid(invite_id):
        return redirect("/notification")

    invite = invite_requests_collection.find_one(
        {"_id": ObjectId(invite_id), "post_owner_email": owner_email}
    )
    if not invite:
        return redirect("/notification")

    owner = current_user_doc() or {}
    discord_username = owner.get("discord_username", "").strip()

    invite_requests_collection.update_one(
        {"_id": invite["_id"]},
        {
            "$set": {
                "status": "approved" if decision == "approve" else "denied",
                "updated_at": time.time(),
                "owner_discord_username": discord_username if decision == "approve" else "",
            }
        },
    )

    return redirect("/notification")


@app.route("/delete-post/<post_id>", methods=["POST"])
def delete_post(post_id):
    validate_csrf()
    user_email = current_user_email()
    if not user_email:
        return redirect("/login")

    posts_collection.delete_one(
        {"_id": ObjectId(post_id), "user_email": user_email}
    )
    return redirect("/profile")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/notification")
def notification():
    user_email = current_user_email()
    if not user_email:
        return redirect("/login")

    incoming_requests = list(
        invite_requests_collection.find(
            {"post_owner_email": user_email, "status": "pending"}
        ).sort("created_at", -1)
    )

    sent_requests = list(
        invite_requests_collection.find(
            {"requester_email": user_email}
        ).sort("created_at", -1)
    )

    return render_template(
        "notification.html",
        incoming_requests=incoming_requests,
        sent_requests=sent_requests,
    )


@app.route("/profile")
def profile():
    user_email = current_user_email()
    if not user_email:
        return redirect("/login")

    user_doc = current_user_doc() or {}
    user_posts = list(
        posts_collection.find({"user_email": user_email}).sort("_id", -1)
    )

    return render_template(
        "profile.html",
        email=user_email,
        posts=[serialize_post(post, user_email) for post in user_posts],
        discord_username=user_doc.get("discord_username", ""),
    )


@app.route("/profile/discord", methods=["POST"])
def update_discord_username():
    validate_csrf()
    enforce_rate_limit("profile_update")
    user_email = current_user_email()
    if not user_email:
        return redirect("/login")

    try:
        discord_username = validate_text_field(
            request.form.get("discord_username", ""),
            "Discord username",
            40,
            required=False,
            pattern=r"[A-Za-z0-9_.#]{0,40}",
        )
    except ValueError as exc:
        return str(exc), 400
    collection.update_one(
        {"email": user_email},
        {"$set": {"discord_username": discord_username}},
    )
    return redirect("/profile")


@app.route("/logout", methods=["POST"])
def logout():
    validate_csrf()
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", error_message="")

    validate_csrf()
    enforce_rate_limit("register")

    email = request.form["email"].strip().lower()
    password = request.form["password"]

    if collection.find_one({"email": email}):
        return render_template(
            "register.html",
            error_message="We could not create that account. Try a different email or log in instead.",
        ), 400

    if len(email) > 254 or "@" not in email:
        return render_template(
            "register.html",
            error_message="Enter a valid email address.",
        ), 400

    if len(password) < 8:
        return render_template(
            "register.html",
            error_message="Password must be at least 8 characters long.",
        ), 400

    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    collection.insert_one(
        {"email": email, "password_hash": pw_hash, "discord_username": ""}
    )

    session["user_email"] = email
    return redirect("/profile")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error_message="")

    validate_csrf()
    enforce_rate_limit("login")

    email = request.form["email"].strip().lower()
    password = request.form["password"]

    user = collection.find_one({"email": email})
    if not user:
        return render_template(
            "login.html",
            error_message="Invalid email or password. Check your credentials and try again.",
        ), 401

    if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"]):
        return render_template(
            "login.html",
            error_message="Invalid email or password. Check your credentials and try again.",
        ), 401

    session["user_email"] = user["email"]
    return redirect("/profile")


@app.route("/contact-sent")
def contact_sent():
    return render_template("contact-sent.html")


@app.route("/game-cover")
def game_cover():
    game_name = request.args.get("name", "").strip()
    if not game_name:
        return jsonify({"image_url": "/static/default-game.jpg"})

    try:
        image_url = get_game_cover(game_name)
    except Exception:
        image_url = "/static/default-game.jpg"

    return jsonify({"image_url": image_url})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
