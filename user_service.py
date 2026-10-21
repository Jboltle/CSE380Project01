class UserService:
    def __init__(self, database):
        self.database = database

    def select_users(self, limit):
        return self.database.fetch_all("SELECT * FROM users LIMIT ?", (limit,))

    def find_username(self, username):
        return self.database.fetch_one("SELECT * FROM users WHERE username = ?", (username,))

    def find_email(self, email_address):
        return self.database.fetch_one("SELECT * FROM users WHERE email_address = ?", (email_address,))

    def find_user(self, username):
        return self.database.fetch_one("SELECT * FROM users WHERE username = ?", (username,))

    def create_user(self, first_name, last_name, username, email_address, pass_hash, salt):
        user_id = self.database.insert(
            "INSERT INTO users (first_name, last_name, username, email_address, password, salt) VALUES (?, ?, ?, ?, ?, ?)",
            (first_name, last_name, username, email_address, pass_hash, salt),
        )
        self.database.insert(
            "INSERT INTO password_history (user_id, pass_hash) VALUES (?, ?)",
            (user_id, pass_hash),
        )

    def username_taken(self, username, user_id):
        row = self.database.fetch_one("SELECT * FROM users WHERE username = ?", (username,))
        return row is not None and row["id"] != user_id

    def update_username(self, user_id, new_username):
        self.database.insert("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))

    def password_used(self, user_id, pass_hash):
        row = self.database.fetch_one(
            "SELECT * FROM password_history WHERE user_id = ? AND pass_hash = ?",
            (user_id, pass_hash),
        )
        return row is not None

    def update_password(self, user_id, pass_hash):
        self.database.insert("UPDATE users SET password = ? WHERE id = ?", (pass_hash, user_id))
        self.database.insert(
            "INSERT INTO password_history (user_id, pass_hash) VALUES (?, ?)",
            (user_id, pass_hash),
        )
