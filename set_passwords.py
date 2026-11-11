
from getpass import getpass
from werkzeug.security import generate_password_hash
from db import get_db_connection

conn = get_db_connection()

if conn is None:
    print("Database connection failed.")
    raise SystemExit

cursor = conn.cursor()

cursor.execute("""
    SELECT user_id, username, full_name
    FROM app_user
    ORDER BY user_id;
""")

users = cursor.fetchall()

print("\n--- DPP USER ACCOUNTS ---")
for user in users:
    print(f"{user[0]}. {user[1]} - {user[2]}")

username = input("\nEnter username to set password: ").strip()

cursor.execute(
    "SELECT user_id FROM app_user WHERE username = %s;",
    (username,)
)

user = cursor.fetchone()

if user is None:
    print("Username not found.")
else:
    password = getpass("Enter new password: ")
    confirm_password = getpass("Confirm password: ")

    if len(password) < 8:
        print("Password must contain at least 8 characters.")
    elif password != confirm_password:
        print("Passwords do not match.")
    else:
        password_hash = generate_password_hash(password)

        cursor.execute("""
            UPDATE app_user
            SET password_hash = %s
            WHERE user_id = %s;
        """, (password_hash, user[0]))

        conn.commit()
        print("Password saved successfully!")

cursor.close()
conn.close()
