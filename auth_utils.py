import hashlib
import os
import jwt

from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")


# ---------------- Password Hashing ----------------

def hash_password(password):

    hash_value = hashlib.sha256(
        password.encode()
    ).hexdigest()

    return hash_value


# ---------------- Create JWT Token ----------------

def create_access_token(user_id):

    payload = {
        "user_id": user_id
    }

    token = jwt.encode(
        payload,
        JWT_SECRET,
        algorithm="HS256"
    )

    return token


# ------------------Verify JWT Token------------------

def verify_access_token(token):
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )

        return payload

    except jwt.InvalidTokenError:
        return None