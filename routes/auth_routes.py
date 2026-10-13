import os
from urllib.parse import urlencode, parse_qs, urlparse

from dotenv import load_dotenv
from pydantic import ValidationError


from auth_utils import create_access_token

from database import get_user_by_email, create_github_user

load_dotenv()
import requests
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
    if response is None:
        handler.send_json(400, {
            "error": "Email already exists"
        })
        return

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

# GITHUB CALLBACK
def handle_github_login(handler):

    client_id = os.getenv("GITHUB_CLIENT_ID")

    params = {
        "client_id": client_id,
        "redirect_uri": "http://localhost:8000/auth/github/callback",
        "scope": "user:email"
    }

    github_url = (
        "https://github.com/login/oauth/authorize?"
        + urlencode(params)
    )

    handler.send_response(302)
    handler.send_header("Location", github_url)
    handler.end_headers()


# GITHUB CALLBACK
def handle_github_callback(handler):

    query = urlparse(handler.path).query
    params = parse_qs(query)

    code = params.get("code", [None])[0]

    if code is None:
        handler.send_json(400, {
            "error": "Authorization code is missing"
        })
        return

    client_id = os.getenv("GITHUB_CLIENT_ID")
    client_secret = os.getenv("GITHUB_CLIENT_SECRET")

    # Exchange authorization code for GitHub access token
    response = requests.post(
        "https://github.com/login/oauth/access_token",
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": "http://localhost:8000/auth/github/callback"
        },
        headers={
            "Accept": "application/json"
        }
    )

    token_data = response.json()

    access_token = token_data.get("access_token")

    if access_token is None:
        handler.send_json(400, {
            "error": "Failed to get GitHub access token",
            "github_response": token_data
        })
        return

    # Get GitHub email information
    email_response = requests.get(
        "https://api.github.com/user/emails",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json"
        }
    )

    github_emails = email_response.json()

    # Find primary and verified email
    github_email = None

    for email_data in github_emails:
        if email_data["primary"] and email_data["verified"]:
            github_email = email_data["email"]
            break

    if github_email is None:
        handler.send_json(400, {
            "error": "Verified GitHub email not found"
        })
        return

    # Get GitHub user information
    user_response = requests.get(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json"
        }
    )

    github_user = user_response.json()

    # Add email to GitHub user information
    github_user["email"] = github_email

    # Check whether this email already exists
    user = get_user_by_email(github_email)

    # Create a new database user if email does not exist
    if user is None:

        github_name = github_user.get("name")

        if github_name is None:
            github_name = github_user.get("login")

        user_id = create_github_user(
            github_name,
            github_email
        )

        # Get the newly created user
        user = get_user_by_email(github_email)

    print("GitHub user:", github_user)
    print("Database user:", user)

    # Create JWT for our application
    app_access_token = create_access_token(user[0])

    # Send successful login response
    handler.send_json(200, {
        "message": "GitHub login successful",
        "id": user[0],
        "name": user[1],
        "email": user[2],
        "access_token": app_access_token
    })