import os
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()


class Database:

    @staticmethod
    def get_connection():
        try:

            conn = psycopg2.connect(
                host=os.getenv("DB_HOST"),
                port=os.getenv("DB_PORT"),
                database=os.getenv("DB_NAME"),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD"),
                cursor_factory=RealDictCursor
            )

            return conn

        except Exception as e:
            print(f"[DATABASE ERROR] {e}")
            return None

    @staticmethod
    def execute(query, values=None):

        conn = Database.get_connection()

        if conn is None:
            return False

        try:

            cur = conn.cursor()

            if values:
                cur.execute(query, values)
            else:
                cur.execute(query)

            conn.commit()

            cur.close()
            conn.close()

            return True

        except Exception as e:

            print(f"[EXECUTE ERROR] {e}")

            conn.rollback()
            conn.close()

            return False

    @staticmethod
    def fetch_all(query, values=None):

        conn = Database.get_connection()

        if conn is None:
            return []

        try:

            cur = conn.cursor()

            if values:
                cur.execute(query, values)
            else:
                cur.execute(query)

            rows = cur.fetchall()

            cur.close()
            conn.close()

            return rows

        except Exception as e:

            print(f"[FETCH ERROR] {e}")

            conn.close()

            return []

    @staticmethod
    def fetch_one(query, values=None):

        conn = Database.get_connection()

        if conn is None:
            return None

        try:

            cur = conn.cursor()

            if values:
                cur.execute(query, values)
            else:
                cur.execute(query)

            row = cur.fetchone()

            cur.close()
            conn.close()

            return row

        except Exception as e:

            print(f"[FETCH ERROR] {e}")

            conn.close()

            return None