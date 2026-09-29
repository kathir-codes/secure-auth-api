# -----------------------import------------------------------------
import os
import psycopg
from dotenv import load_dotenv

load_dotenv()


# ---------------------- Database Connection ----------------------

def get_connection():
    connection = psycopg.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        sslmode="require"
    )

    return connection

# ---------------------- Create table ----------------------------------

def create_users_table():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            name TEXT,
            email TEXT UNIQUE,
            password_hash TEXT
        )
    """)

    connection.commit()
    connection.close()

def add_email_unique_constraint():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        ALTER TABLE users
        ADD CONSTRAINT users_email_unique UNIQUE (email)
    """)

    connection.commit()
    connection.close()

# ----------------------- Insert signup user --------------------------

def create_signup_user(name, email, password_hash):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO users (name, email, password_hash)
        VALUES (%s, %s, %s)
        RETURNING id
    """, (name, email, password_hash))

    user_id = cursor.fetchone()[0]

    connection.commit()
    connection.close()

    return user_id

# ------------------- Select All ---------------------------------------

def get_all_users():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM users
    """)

    users = cursor.fetchall()

    connection.close()

    return users

# ---------------------- Select specific -------------------------------

# -------> get by email 
    
def get_user_by_email(email):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT * FROM users
        WHERE email = %s
        """,
        (email,)
    )

    user = cursor.fetchone()

    connection.close()

    return user 

# --------> Get User By ID 

def get_user_by_id(user_id):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT * FROM users
        WHERE id = %s
        """,
        (user_id,)
    )

    user = cursor.fetchone()

    connection.close()

    return user

# ----------------------- Update user ----------------------------------

def update_user(user_id, name, email):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE users
        SET name = %s, email = %s
        WHERE id = %s
        """,
        (name, email, user_id)
    )

    connection.commit()
    connection.close()
# ------------------------update password-----------------------------
def update_user_password(user_id, password_hash):

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE users
        SET password_hash = %s
        WHERE id = %s
        """,
        (password_hash, user_id)
    )

    connection.commit()

    cursor.close()
    connection.close()

# ------------------------- Update partial ----------------------------

def update_user_partial(user_id, name=None, email=None):
    connection = get_connection()
    cursor = connection.cursor()

    if name is not None and email is not None:
        cursor.execute(
            """
            UPDATE users
            SET name = %s, email = %s
            WHERE id = %s
            """,
            (name, email, user_id)
        )

    elif name is not None:
        cursor.execute(
            """
            UPDATE users
            SET name = %s
            WHERE id = %s
            """,
            (name, user_id)
        )

    elif email is not None:
        cursor.execute(
            """
            UPDATE users
            SET email = %s
            WHERE id = %s
            """,
            (email, user_id)
        )

    connection.commit()
    connection.close()

# --------------------------- Delete -----------------------------------

def delete_user(user_id):
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        DELETE FROM users
        WHERE id = %s
        """,
        (user_id,)
    )

    connection.commit()
    connection.close()

