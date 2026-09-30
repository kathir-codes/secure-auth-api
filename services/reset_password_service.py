from database import update_user_password
from auth_utils import (
    verify_password_reset_token,
    hash_password
)


def reset_password_service(user_id, token, new_password):

    # 1. Verify token validity, purpose, and user ID
    payload = verify_password_reset_token(token, user_id)

    if not payload:
        return False

    # 2. Hash new password
    password_hash = hash_password(new_password)

    # 3. Update password in database
    update_user_password(user_id, password_hash)

    return True