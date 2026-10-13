from database import create_signup_user, get_user_by_email
from auth_utils import hash_password
from dto import SignupResponse

def signup_service(name, email, password):

    existing_user = get_user_by_email(email)

    if existing_user:
        return None

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