DROP TABLE IF EXISTS password_history;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE,
    email_address TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    salt TEXT NOT NULL
);

CREATE TABLE password_history (
    user_id INTEGER NOT NULL,
    pass_hash TEXT NOT NULL
);
