import base64
import hashlib
import hmac
import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(BASE_DIR, "key.txt")


class Jwt:
    def get_jwt(self):
        key_file = open(KEY_PATH, "r", encoding="utf-8")
        try:
            key = key_file.read().strip()
        except Exception:
            key_file.close()
            raise
        key_file.close()
        return key

    def make_jwt(self, username):
        header = base64.b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8")).decode("utf-8")
        payload = base64.b64encode(json.dumps({"username": username, "access": "True"}).encode("utf-8")).decode("utf-8")
        message = f"{header}.{payload}".encode("utf-8")
        signature = hmac.new(self.get_jwt().encode("utf-8"), message, hashlib.sha256).hexdigest()
        return f"{header}.{payload}.{signature}"

    def compare_jwt(self, token):
        parts = token.split(".")
        if len(parts) != 3:
            return False
        header, payload, signature = parts
        message = f"{header}.{payload}".encode("utf-8")
        expected_signature = hmac.new(self.get_jwt().encode("utf-8"), message, hashlib.sha256).hexdigest()
        return expected_signature == signature

    def read_jwt(self, token):
        if not self.compare_jwt(token):
            return None
        payload = token.split(".")[1] #gets the other side of the jwt ey ..... etc 
        decoded = json.loads(base64.b64decode(payload.encode("utf-8")))
        if decoded["access"] != "True":
            return None
        return decoded["username"]
