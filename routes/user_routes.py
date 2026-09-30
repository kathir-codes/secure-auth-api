from pydantic import ValidationError

from dto import (
    UpdateUserRequest,
    PartialUpdateUserRequest
)

from database import get_user_by_id

from services.user_service import (
    get_all_users_service,
    get_user_service,
    update_user_service,
    update_user_partial_service,
    delete_user_service
)

#-----------------GET Method----------------------------------
# GET ALL USERS
def handle_get_all_users(handler):

    response = get_all_users_service()

    handler.send_json(200, response)


# GET USER BY ID
def handle_get_user(handler):

    user_id = handler.get_user_id()

    if user_id is None:
        return

    response = get_user_service(user_id)

    if response is None:
        handler.send_json(404, {
            "error": "User not found"
        })
        return

    handler.send_json(200, response)

#-----------------PUT Method----------------------------------
# PUT - FULL USER UPDATE
def handle_update_user(handler):

    user_id = handler.get_user_id()

    if user_id is None:
        return

    payload = handler.authenticate_request(user_id)

    if payload is None:
        return
    #not neccessary
    user = get_user_by_id(user_id)

    if user is None:
        handler.send_json(404, {
            "error": "User not found"
        })
        return

    try:
        data = handler.read_json()
        update_request = UpdateUserRequest(**data)

    except (ValidationError, ValueError, TypeError):
        handler.send_json(400, {
            "error": "Name and email are required"
        })
        return

    response = update_user_service(
        user_id,
        update_request.name,
        update_request.email
    )

    handler.send_json(200, response)

#-----------------PATCH Method----------------------------------
# PATCH - PARTIAL USER UPDATE
def handle_update_user_partial(handler):

    user_id = handler.get_user_id()

    if user_id is None:
        return

    payload = handler.authenticate_request(user_id)

    if payload is None:
        return

    user = get_user_by_id(user_id)

    if user is None:
        handler.send_json(404, {
            "error": "User not found"
        })
        return

    try:
        data = handler.read_json()
        update_request = PartialUpdateUserRequest(**data)

    except (ValidationError, ValueError, TypeError):
        handler.send_json(400, {
            "error": "Invalid request data"
        })
        return

    update_data = update_request.model_dump(
        exclude_unset=True
    )

    if not update_data:
        handler.send_json(400, {
            "error": "Name or email is required"
        })
        return

    response = update_user_partial_service(
        user_id,
        update_data
    )

    handler.send_json(200, response)

#-----------------DELETE Method----------------------------------
# DELETE USER
def handle_delete_user(handler):

    user_id = handler.get_user_id()

    if user_id is None:
        return

    payload = handler.authenticate_request(user_id)

    if payload is None:
        return

    user = get_user_by_id(user_id)

    if user is None:
        handler.send_json(404, {
            "error": "User not found"
        })
        return

    response = delete_user_service(user_id)

    handler.send_json(200, response)