from database import get_user_by_email
from auth_utils import hash_password, create_access_token, verify_password
from dto import SigninResponse


def signin_service(email, password):

    # 1. Find user by email
    user = get_user_by_email(email)

    if not user:
        return None

    # 2. Verify entered password
    if not verify_password(password, user[3]):
        return None

    # 3. Generate access token
    access_token = create_access_token(user[0])

    # 4. Prepare response
    response = SigninResponse(
        id=user[0],
        name=user[1],
        email=user[2],
        message="User signed in successfully",
        access_token=access_token
    )

    return response.model_dump()