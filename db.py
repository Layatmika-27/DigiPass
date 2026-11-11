
import psycopg2
import os
from dotenv import load_dotenv

# Load database configuration from .env
load_dotenv()

def get_db_connection():
    try:
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
