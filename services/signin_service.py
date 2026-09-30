from database import get_user_by_email
from auth_utils import hash_password, create_access_token
from dto import SigninResponse


def signin_service(email, password):

    # 1. Find user by email
    user = get_user_by_email(email)

    if not user:
        return None

    # 2. Hash the entered password
    password_hash = hash_password(password)

    # 3. Compare with stored password hash
    if password_hash != user[3]:
        return None

    # 4. Generate access token
    access_token = create_access_token(user[0])

    # 5. Prepare response
    # 5. Prepare response
    response = SigninResponse(
        id=user[0],
        name=user[1],
        email=user[2],
        message="User signed in successfully",
        access_token=access_token
    )

    return response.model_dump()