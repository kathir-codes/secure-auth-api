import hashlib
import os
import jwt
import secrets

from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")

# ---------------- Password Hashing ----------------

def hash_password(password):

    salt = secrets.token_bytes(16)

    hash_value = hashlib.sha256(
        salt + password.encode()
    ).hexdigest()

    return salt.hex() + ":" + hash_value

# -----------------verify password-----------------

def verify_password(password, stored_value):

    salt_hex, stored_hash = stored_value.split(":")

    salt = bytes.fromhex(salt_hex)

    hash_value = hashlib.sha256(
        salt + password.encode()
    ).hexdigest()

    return hash_value == stored_hash

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

# -------------------Forget Password------------------

from datetime import datetime, timedelta, timezone

def create_password_reset_token(user_id):
    payload = {
        "user_id": user_id,
        "purpose": "password_reset",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15)
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    return token

# --------------------Reset Password--------------------

def verify_password_reset_token(token, expected_user_id):
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )

        # Check token purpose
        if payload.get("purpose") != "password_reset":
            return None

        # Check user ID
        if payload.get("user_id") != expected_user_id:
            return None

        return payload

    except jwt.InvalidTokenError:
        return None