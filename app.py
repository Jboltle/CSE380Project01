import hashlib
import json

from flask import Flask, request

from database import Database
from jwt import Jwt
from user_service import UserService

app = Flask(__name__)

MIN_PASSWORD_LENGTH = 8
NULL_VALUE = "NULL"
SUCCESS = 1

database = Database()
users = UserService(database)
tokens = Jwt()


def respond(payload):
    return json.dumps(payload), 200, {"Content-Type": "application/json"} # json response type we want to be returened


def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode("utf-8")).hexdigest()


def password_meets_rules(password, first_name, last_name, username):
    if len(password) < MIN_PASSWORD_LENGTH:
        return False
    if not any(character.islower() for character in password): #imma do my own thing and just use smart pattern matching like in rust 
        return False
    if not any(character.isupper() for character in password):
        return False
    if not any(character.isdigit() for character in password):
        return False
    lowered_password = password.lower()
    for identity in (first_name, last_name, username):
        if identity and identity.lower() in lowered_password:
            return False
    return True


@app.route("/", methods=["GET"])
def index():
    return users.select_users(10)


@app.route("/clear", methods=["GET"])
def clear():
    database.delete_db()
    return ""


@app.route("/create_user", methods=["POST"])
def create_user():
    first_name = request.form["first_name"]
    last_name = request.form["last_name"]
    username = request.form["username"]
    email_address = request.form["email_address"]
    password = request.form["password"]
    salt = request.form["salt"]

    if users.find_username(username) is not None:
        return respond({"status": 2, "pass_hash": NULL_VALUE})
    if users.find_email(email_address) is not None:
        return respond({"status": 3, "pass_hash": NULL_VALUE})
    if not password_meets_rules(password, first_name, last_name, username):
        return respond({"status": 4, "pass_hash": NULL_VALUE})

    pass_hash = hash_password(password, salt)
    users.create_user(first_name, last_name, username, email_address, pass_hash, salt)
    return respond({"status": SUCCESS, "pass_hash": pass_hash})


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    user = users.find_user(username)
    if user is None:
        return respond({"status": 2, "jwt": NULL_VALUE})

    pass_hash = hash_password(password, user["salt"])
    if pass_hash != user["password"]:
        return respond({"status": 2, "jwt": NULL_VALUE})
    return respond({"status": SUCCESS, "jwt": tokens.make_jwt(user["username"])})


@app.route("/update", methods=["POST"])
def update():
    token_username = tokens.read_jwt(request.form["jwt"])
    if token_username is None:
        return respond({"status": 3})

    user = users.find_user(token_username)
    if user is None:
        return respond({"status": 3})

    if "new_username" in request.form:
        current_username = request.form["username"]
        new_username = request.form["new_username"]
        if current_username != user["username"]:
            return respond({"status": 2})
        if users.username_taken(new_username, user["id"]):
            return respond({"status": 2})
        users.update_username(user["id"], new_username)
        return respond({"status": SUCCESS})

    if "new_password" in request.form:
        current_password = request.form["password"]
        new_password = request.form["new_password"]
        current_hash = hash_password(current_password, user["salt"])
        if current_hash != user["password"]:
            return respond({"status": 2})
        if not password_meets_rules(new_password, user["first_name"], user["last_name"], user["username"]):
            return respond({"status": 2})
        new_hash = hash_password(new_password, user["salt"])
        if users.password_used(user["id"], new_hash):
            return respond({"status": 2})
        users.update_password(user["id"], new_hash)
        return respond({"status": SUCCESS})

    return respond({"status": 2})


@app.route("/view", methods=["POST"])
def view():
    token_username = tokens.read_jwt(request.form["jwt"])
    if token_username is None:
        return respond({"status": 2, "data": NULL_VALUE})

    user = users.find_user(token_username)
    if user is None:
        return respond({"status": 2, "data": NULL_VALUE})

    return respond({
        "status": SUCCESS,
        "data": {
            "username": user["username"],
            "email_address": user["email_address"],
            "first_name": user["first_name"],
            "last_name": user["last_name"],
        },
    })


@app.route("/test_get", methods=["GET"])
def test_get():
    return request.args.get("numbers")


@app.route("/test_post", methods=["POST"])
def test_post():
    return request.form


database.delete_db()
