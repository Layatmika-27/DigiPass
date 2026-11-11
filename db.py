import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()


def get_db_connection():
    try:
        use_neon = os.getenv("USE_NEON", "False").strip().lower() == "true"

        if use_neon:
            connection = psycopg2.connect(
                host=os.getenv("NEON_DB_HOST"),
                database=os.getenv("NEON_DB_NAME"),
                user=os.getenv("NEON_DB_USER"),
                password=os.getenv("NEON_DB_PASSWORD"),
                port=os.getenv("NEON_DB_PORT", "5432"),
                sslmode=os.getenv("NEON_DB_SSLMODE", "require")
            )
        else:
            connection = psycopg2.connect(
                host=os.getenv("DB_HOST"),
                database=os.getenv("DB_NAME"),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD"),
                port=os.getenv("DB_PORT")
            )

        return connection

    except Exception as e:
        print("Database connection failed:", e)
        return None