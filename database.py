import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "project1.db")
SQL_PATH = os.path.join(BASE_DIR, "project1.sql")


class Database:
    def delete_db(self):
        if os.path.exists(DB_PATH):
            os.remove(DB_PATH)

    def _initialize(self):
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

    def _connect(self):
        if not os.path.exists(DB_PATH):
            self._initialize()
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row # we use this so we can access database patterns like json or a dictionary 
        return conn

    def _execute(self, query, values):
        conn = self._connect()
        try:
            cursor = conn.cursor()
            cursor.execute(query, values)
            rows = cursor.fetchall()
            row_id = cursor.lastrowid
            conn.commit()
        except Exception:
            conn.close()
            raise
        conn.close()
        return rows, row_id

    def fetch_all(self, query, values=()):
        rows, row_id = self._execute(query, values)
        return rows

    def fetch_one(self, query, values=()):
        rows = self.fetch_all(query, values)
        if len(rows) == 0:
            return None
        return rows[0]

    def insert(self, query, values):
        rows, row_id = self._execute(query, values)
        return row_id
