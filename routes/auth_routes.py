from pydantic import ValidationError

from dto import (
    SignupRequest,
    SigninRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest
)

from services.auth_service import signup_service
from services.signin_service import signin_service
from services.forgot_password_service import forgot_password_service
from services.reset_password_service import reset_password_service


# SIGNUP
def handle_signup(handler):

    try:
        data = handler.read_json()
        signup_request = SignupRequest(**data)

    except (ValidationError, ValueError, TypeError):
        handler.send_json(400, {
            "error": "Name, email and password are required"
        })
        return

    response = signup_service(
        signup_request.name,
        signup_request.email,
        signup_request.password
    )

    handler.send_json(201, response)


# SIGNIN
def handle_signin(handler):

    try:
        data = handler.read_json()
        signin_request = SigninRequest(**data)

    except (ValidationError, ValueError, TypeError):
        handler.send_json(400, {
            "error": "Email and password are required"
        })
        return

    response = signin_service(
        signin_request.email,
        signin_request.password
    )

    if response is None:
        handler.send_json(401, {
            "error": "Invalid email or password"
        })
        return

    handler.send_json(200, response)


# FORGOT PASSWORD
def handle_forgot_password(handler):

    try:
        data = handler.read_json()
        forgot_request = ForgotPasswordRequest(**data)

    except (ValidationError, ValueError, TypeError):
        handler.send_json(400, {
            "error": "Email is required"
        })
        return

    forgot_password_service(
        forgot_request.email
    )

    handler.send_json(200, {
        "message": "If the email exists, a password reset link will be sent"
    })


# RESET PASSWORD
def handle_reset_password(handler):

    try:
        data = handler.read_json()
        reset_request = ResetPasswordRequest(**data)

    except (ValidationError, ValueError, TypeError):
        handler.send_json(400, {
            "error": "User ID, token and new password are required"
        })
        return

    success = reset_password_service(
        reset_request.user_id,
        reset_request.token,
        reset_request.new_password
    )

    if not success:
        handler.send_json(400, {
            "error": "Invalid or expired reset token"
        })
        return

    handler.send_json(200, {
        "message": "Password reset successfully"
    })