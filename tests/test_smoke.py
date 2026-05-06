import importlib
import os


os.environ.setdefault("FLASK_SECRET_KEY", "test-secret")
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")
os.environ.setdefault("TWITCH_CLIENT_ID", "test-client")
os.environ.setdefault("TWITCH_CLIENT_SECRET", "test-secret")

app_module = importlib.import_module("TeamSwipe")
app = app_module.app
app.config["TESTING"] = True


def test_login_page_renders():
    client = app.test_client()
    response = client.get("/login")
    assert response.status_code == 200


def test_register_page_renders():
    client = app.test_client()
    response = client.get("/register")
    assert response.status_code == 200
