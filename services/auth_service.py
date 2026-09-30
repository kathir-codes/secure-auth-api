from database import create_signup_user
from auth_utils import hash_password
from dto import SignupResponse


def signup_service(name, email, password):

    password_hash = hash_password(password)

    user_id = create_signup_user(
        name,
        email,
        password_hash
    )

    response = SignupResponse(
        message="User signed up successfully",
        id=user_id,
        name=name,
        email=email
    )

    return response.model_dump()