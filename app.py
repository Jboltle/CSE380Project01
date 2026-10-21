import base64
import hashlib
import hmac
import json
import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "project1.db")
SQL_PATH = os.path.join(BASE_DIR, "project1.sql")
KEY_PATH = os.path.join(BASE_DIR, "key.txt")

MIN_PASSWORD_LENGTH = 8
NULL_VALUE = "NULL"
SUCCESS = 1


def delete_db_file():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)


def initialize_db():
    conn = sqlite3.connect(DB_PATH)
    sql_file = None
    try:
        sql_file = open(SQL_PATH, "r", encoding="utf-8")
        conn.executescript(sql_file.read())
    except Exception:
        if sql_file is not None:
            sql_file.close()
        conn.close()
        raise
    sql_file.close()
    conn.close()


def get_db():
    if not os.path.exists(DB_PATH):
        initialize_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/', methods=(['GET']))
def index():
	conn = get_db()
	try:
		cursor = conn.cursor()
		cursor.execute("SELECT * FROM users LIMIT 10;")
		result = cursor.fetchall()
		conn.commit()
	except Exception:
		conn.close()
		raise
	conn.close()
	return result


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


def read_key():
    key_file = open(KEY_PATH, "r", encoding="utf-8")
    try:
        key = key_file.read().strip()
    except Exception:
        key_file.close()
        raise
    key_file.close()
    return key


def make_jwt(username):
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8")).decode("utf-8")
    payload = base64.urlsafe_b64encode(json.dumps({"username": username, "access": "True"}).encode("utf-8")).decode("utf-8")
    message = f"{header}.{payload}".encode("utf-8")
    signature = hmac.new(read_key().encode("utf-8"), message, hashlib.sha256).hexdigest()
    return f"{header}.{payload}.{signature}"


def read_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header, payload, signature = parts
    message = f"{header}.{payload}".encode("utf-8")
    expected_signature = hmac.new(read_key().encode("utf-8"), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        return None
    try:
        decoded = json.loads(base64.urlsafe_b64decode(payload.encode("utf-8")))
    except (json.JSONDecodeError, ValueError):
        return None
    if decoded.get("access") != "True":
        return None
    username = decoded.get("username")
    if not isinstance(username, str) or username == "":
        return None
    return username


def fetch_user(cursor, username):
    cursor.execute(
        "SELECT id, first_name, last_name, username, email_address, password, salt FROM users WHERE username = ?",
        (username,),
    )
    return cursor.fetchone()


def password_was_used(cursor, user_id, pass_hash):
    cursor.execute(
        "SELECT 1 FROM password_history WHERE user_id = ? AND pass_hash = ?",
        (user_id, pass_hash),
    )
    return cursor.fetchone() is not None


@app.route("/clear", methods=["GET"])
def clear():
    delete_db_file()
    return ""


@app.route("/create_user", methods=["POST"])
def create_user():
    first_name = request.form["first_name"]
    last_name = request.form["last_name"]
    username = request.form["username"]
    email_address = request.form["email_address"]
    password = request.form["password"]
    salt = request.form["salt"]

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            response = respond({"status": 2, "pass_hash": NULL_VALUE})
        else:
            cursor.execute("SELECT 1 FROM users WHERE email_address = ?", (email_address,))
            if cursor.fetchone() is not None:
                response = respond({"status": 3, "pass_hash": NULL_VALUE})
            elif not password_meets_rules(password, first_name, last_name, username):
                response = respond({"status": 4, "pass_hash": NULL_VALUE})
            else:
                pass_hash = hash_password(password, salt)
                cursor.execute(
                    "INSERT INTO users (first_name, last_name, username, email_address, password, salt) VALUES (?, ?, ?, ?, ?, ?)",
                    (first_name, last_name, username, email_address, pass_hash, salt),
                )
                cursor.execute(
                    "INSERT INTO password_history (user_id, pass_hash) VALUES (?, ?)",
                    (cursor.lastrowid, pass_hash),
                )
                response = respond({"status": SUCCESS, "pass_hash": pass_hash})
        conn.commit()
    except Exception:
        conn.close()
        raise
    conn.close()
    return response


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    conn = get_db()
    try:
        cursor = conn.cursor()
        user = fetch_user(cursor, username)
        if user is None:
            response = respond({"status": 2, "jwt": NULL_VALUE})
        else:
            pass_hash = hash_password(password, user["salt"])
            if not hmac.compare_digest(pass_hash, user["password"]):
                response = respond({"status": 2, "jwt": NULL_VALUE})
            else:
                response = respond({"status": SUCCESS, "jwt": make_jwt(user["username"])})
        conn.commit()
    except Exception:
        conn.close()
        raise
    conn.close()
    return response


@app.route("/update", methods=["POST"])
def update():
    token_username = read_jwt(request.form["jwt"])
    if token_username is None:
        return respond({"status": 3})

    conn = get_db()
    try:
        cursor = conn.cursor()
        user = fetch_user(cursor, token_username)
        if user is None:
            response = respond({"status": 3})
        elif "new_username" in request.form:
            current_username = request.form["username"]
            new_username = request.form["new_username"]
            if current_username != user["username"]:
                response = respond({"status": 2})
            else:
                cursor.execute("SELECT 1 FROM users WHERE username = ? AND id != ?", (new_username, user["id"]))
                if cursor.fetchone() is not None:
                    response = respond({"status": 2})
                else:
                    cursor.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user["id"]))
                    response = respond({"status": SUCCESS})
        elif "new_password" in request.form:
            current_password = request.form["password"]
            new_password = request.form["new_password"]
            current_hash = hash_password(current_password, user["salt"])
            if not hmac.compare_digest(current_hash, user["password"]):
                response = respond({"status": 2})
            elif not password_meets_rules(new_password, user["first_name"], user["last_name"], user["username"]):
                response = respond({"status": 2})
            else:
                new_hash = hash_password(new_password, user["salt"])
                if password_was_used(cursor, user["id"], new_hash):
                    response = respond({"status": 2})
                else:
                    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_hash, user["id"]))
                    cursor.execute(
                        "INSERT INTO password_history (user_id, pass_hash) VALUES (?, ?)",
                        (user["id"], new_hash),
                    )
                    response = respond({"status": SUCCESS})
        else:
            response = respond({"status": 2})
        conn.commit()
    except Exception:
        conn.close()
        raise
    conn.close()
    return response


@app.route("/view", methods=["POST"])
def view():
    token_username = read_jwt(request.form["jwt"])
    if token_username is None:
        return respond({"status": 2, "data": NULL_VALUE})

    conn = get_db()
    try:
        cursor = conn.cursor()
        user = fetch_user(cursor, token_username)
        if user is None:
            response = respond({"status": 2, "data": NULL_VALUE})
        else:
            response = respond({
                "status": SUCCESS,
                "data": {
                    "username": user["username"],
                    "email_address": user["email_address"],
                    "first_name": user["first_name"],
                    "last_name": user["last_name"],
                },
            })
        conn.commit()
    except Exception:
        conn.close()
        raise
    conn.close()
    return response


@app.route("/test_get", methods=["GET"])
def test_get():
    return request.args.get("numbers")


@app.route("/test_post", methods=["POST"])
def test_post():
    return request.form


delete_db_file()
