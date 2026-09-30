from database import (
    get_all_users,
    get_user_by_id,
    update_user,
    update_user_partial,
    delete_user
)

from dto import (
    UserResponse,
    UserUpdateResponse,
    MessageResponse
)


# GET ALL USERS
def get_all_users_service():

    users = get_all_users()

    response = []

    for user in users:

        user_response = UserResponse(
            id=user[0],
            name=user[1],
            email=user[2]
        )

        response.append(
            user_response.model_dump()
        )

    return response


# GET USER BY ID
def get_user_service(user_id):

    user = get_user_by_id(user_id)

    if user is None:
        return None

    response = UserResponse(
        id=user[0],
        name=user[1],
        email=user[2]
    )

    return response.model_dump()


# FULL USER UPDATE
def update_user_service(user_id, name, email):

    update_user(
        user_id,
        name,
        email
    )

    response = UserUpdateResponse(
        message="User updated successfully",
        id=user_id,
        name=name,
        email=email
    )

    return response.model_dump()


# PARTIAL USER UPDATE
def update_user_partial_service(user_id, update_data):

    update_user_partial(
        user_id,
        update_data.get("name"),
        update_data.get("email")
    )

    updated_user = get_user_by_id(user_id)

    response = UserUpdateResponse(
        message="User partially updated",
        id=updated_user[0],
        name=updated_user[1],
        email=updated_user[2]
    )

    return response.model_dump()


# DELETE USER
def delete_user_service(user_id):

    delete_user(user_id)

    response = MessageResponse(
        message="User deleted successfully",
        id=user_id
    )

    return response.model_dump()