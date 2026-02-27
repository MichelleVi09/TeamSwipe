from flask import Flask, render_template, request, redirect, session
from pymongo import MongoClient
import certifi
import bcrypt
import os
from dotenv import load_dotenv

load_dotenv()

# creating app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

#creating db
MONGODB_URI = os.getenv("MONGODB_URI")
if not MONGODB_URI:
    raise ValueError("Missing MONGODB_URI. Put it in your .env file.")

client = MongoClient(MONGODB_URI, tlsCAFile=certifi.where())

#getting db info
db = client["TeamSwipe"]
collection = db["users"]

#home page
@app.route("/")
def home():
    return render_template("Index.html")

#where users will be able to find posts
@app.route("/browse")
def browse():
    return render_template("browse.html")

#where users can create their own posts
@app.route("/create")
def create():
    return render_template("create.html")


#own credentials to report problems
@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/notification")
def notification():
    return render_template("notification.html")

@app.route("/profile")
def profile():
    #if user hasn't logged in, profile page redirects to login page
    if "user_email" not in session:
        return redirect("/login")
    return render_template("profile.html", email=session["user_email"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    email = request.form["email"].strip().lower()
    password = request.form["password"]

    if collection.find_one({"email": email}):
        return "Email already exists", 400

    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    collection.insert_one({
        "email": email,
        "password_hash": pw_hash
    })

    # auto-login after signup
    session["user_email"] = email
    return redirect("/profile")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = request.form["email"].strip().lower()
    password = request.form["password"]

    user = collection.find_one({"email": email})
    if not user:
        return "Invalid email or password", 401

    if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"]):
        return "Invalid email or password", 401

    session["user_email"] = user["email"]
    return redirect("/profile")



if __name__ == "__main__":
    app.run()
