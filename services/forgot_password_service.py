from database import get_user_by_email
from auth_utils import create_password_reset_token


def forgot_password_service(email):

    # 1. Find user by email
    user = get_user_by_email(email)

    if not user:
        return None

    # 2. Generate password reset token
    reset_token = create_password_reset_token(user[0])

    # 3. Print token for development testing
    print("Password Reset Token:", reset_token)

    return {
        "message": "If the email exists, a password reset link will be sent"
    }