from http.server import HTTPServer, BaseHTTPRequestHandler
import json

from pydantic import ValidationError

from dto import (
    SignupRequest,
    SigninRequest,
    UpdateUserRequest,
    PartialUpdateUserRequest,
    SignupResponse,
    SigninResponse,
    UserResponse,
    MessageResponse,
    UserUpdateResponse,
    ForgotPasswordRequest,
    ResetPasswordRequest
)

from database import (
    create_users_table,
    get_all_users,
    get_user_by_email,
    get_user_by_id,
    update_user,
    update_user_partial,
    delete_user,
    create_signup_user,
    update_user_password
)

from auth_utils import (
    hash_password,
    create_access_token,
    verify_access_token,
    create_password_reset_token,
    verify_password_reset_token
)


# Initialize database
create_users_table()


class MyHandler(BaseHTTPRequestHandler):

    # --------------------------------------------------
    # REUSABLE 
    # --------------------------------------------------

    def send_json(self, status_code, data):

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        response_data = json.dumps(data).encode()

        self.wfile.write(response_data)

    def read_json(self):

        content_length = int(
            self.headers.get("Content-Length", 0)
        )

        body = self.rfile.read(content_length)

        return json.loads(body)

    def get_user_id(self):

        try:
            return int(self.path.split("/")[-1])

        except ValueError:
            self.send_json(400, {
                "error": "Invalid user ID"
            })
            return None

    # --------------------------------------------------
    # AUTHENTICATION
    # --------------------------------------------------

    def authenticate_request(self, requested_user_id=None):

        authorization = self.headers.get("Authorization")

        if authorization is None:
            self.send_json(401, {
                "error": "Authorization header is required"
            })
            return None

        if not authorization.startswith("Bearer "):
            self.send_json(401, {
                "error": "Invalid authorization format"
            })
            return None

        token = authorization.split(" ", 1)[1].strip()

        payload = verify_access_token(token)

        if payload is None:
            self.send_json(401, {
                "error": "Invalid or expired token"
            })
            return None

        if requested_user_id is not None:

            logged_in_user_id = payload["user_id"]

            if logged_in_user_id != requested_user_id:
                self.send_json(403, {
                    "error": "Access denied"
                })
                return None

        return payload

    # --------------------------------------------------
    # GET
    # --------------------------------------------------

    def do_GET(self):

        # GET ALL USERS
        if self.path == "/users":

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

            self.send_json(200, response)

            return

        # GET USER BY ID
        if self.path.startswith("/users/"):

            user_id = self.get_user_id()

            if user_id is None:
                return

            user = get_user_by_id(user_id)

            if user is None:
                self.send_json(404, {
                    "error": "User not found"
                })
                return

            response = UserResponse(
                id=user[0],
                name=user[1],
                email=user[2]
            )

            self.send_json(
                200,
                response.model_dump()
            )

            return

        # UNKNOWN URL
        self.send_json(404, {
            "error": "Not Found"
        })

    # --------------------------------------------------
    # POST
    # --------------------------------------------------

    def do_POST(self):

        # SIGNIN
        if self.path == "/signin":

            try:
                data = self.read_json()
                signin_request = SigninRequest(**data)

            except (ValidationError, ValueError, TypeError):
                self.send_json(400, {
                    "error": "Email and password are required"
                })
                return

            user = get_user_by_email(
                signin_request.email
            )

            if user is None:
                self.send_json(401, {
                    "error": "Invalid email or password"
                })
                return

            password_hash = hash_password(
                signin_request.password
            )

            if password_hash != user[3]:
                self.send_json(401, {
                    "error": "Invalid email or password"
                })
                return

            token = create_access_token(user[0])

            response = SigninResponse(
                message="Signin successful",
                id=user[0],
                name=user[1],
                email=user[2],
                access_token=token
            )

            self.send_json(
                200,
                response.model_dump()
            )

            return

        # SIGNUP
        if self.path == "/signup":

            try:
                data = self.read_json()
                signup_request = SignupRequest(**data)

            except (ValidationError, ValueError, TypeError):
                self.send_json(400, {
                    "error": "Name, email and password are required"
                })
                return

            password_hash = hash_password(
                signup_request.password
            )

            user_id = create_signup_user(
                signup_request.name,
                signup_request.email,
                password_hash
            )

            response = SignupResponse(
                message="User signed up successfully",
                id=user_id,
                name=signup_request.name,
                email=signup_request.email
            )

            self.send_json(
                201,
                response.model_dump()
            )

            return

        # FORGOT PASSWORD
        if self.path == "/forgot-password":

            try:
                data = self.read_json()
                forgot_request = ForgotPasswordRequest(**data)

            except (ValidationError, ValueError, TypeError):
                self.send_json(400, {
                    "error": "Email is required"
                })
                return

            user = get_user_by_email(
                forgot_request.email
            )

            if user is not None:

                reset_token = create_password_reset_token(
                    user[0]
                )

                # Development only
                print("Password reset token:", reset_token)

            self.send_json(200, {
                "message": "If the account exists, a password reset link has been sent."
            })

            return

        # RESET PASSWORD
        if self.path == "/reset-password":

            try:
                data = self.read_json()
                reset_request = ResetPasswordRequest(**data)

            except (ValidationError, ValueError, TypeError):
                self.send_json(400, {
                    "error": "Token and new password are required"
                })
                return

            payload = verify_password_reset_token(
                reset_request.token,
                reset_request.user_id
            )

            if payload is None:
                self.send_json(401, {
                    "error": "Invalid or expired reset token"
                })
                return

            user_id = payload["user_id"]

            password_hash = hash_password(
                reset_request.new_password
            )

            update_user_password(
                user_id,
                password_hash
            )

            self.send_json(200, {
                "message": "Password reset successfully"
            })

            return

        # UNKNOWN POST URL
        self.send_json(404, {
            "error": "Not Found"
        })

    # --------------------------------------------------
    # PUT - FULL USER UPDATE
    # --------------------------------------------------

    def do_PUT(self):

        user_id = self.get_user_id()

        if user_id is None:
            return

        payload = self.authenticate_request(user_id)

        if payload is None:
            return

        user = get_user_by_id(user_id)

        if user is None:
            self.send_json(404, {
                "error": "User not found"
            })
            return

        try:
            data = self.read_json()
            update_request = UpdateUserRequest(**data)

        except (ValidationError, ValueError, TypeError):
            self.send_json(400, {
                "error": "Name and email are required"
            })
            return

        update_user(
            user_id,
            update_request.name,
            update_request.email
        )

        response = UserUpdateResponse(
            message="User updated successfully",
            id=user_id,
            name=update_request.name,
            email=update_request.email
        )

        self.send_json(
            200,
            response.model_dump()
        )

    # --------------------------------------------------
    # PATCH - PARTIAL USER UPDATE
    # --------------------------------------------------

    def do_PATCH(self):

        user_id = self.get_user_id()

        if user_id is None:
            return

        payload = self.authenticate_request(user_id)

        if payload is None:
            return

        user = get_user_by_id(user_id)

        if user is None:
            self.send_json(404, {
                "error": "User not found"
            })
            return

        try:
            data = self.read_json()
            update_request = PartialUpdateUserRequest(**data)

        except (ValidationError, ValueError, TypeError):
            self.send_json(400, {
                "error": "Invalid request data"
            })
            return

        update_data = update_request.model_dump(
            exclude_unset=True
        )

        if not update_data:
            self.send_json(400, {
                "error": "Name or email is required"
            })
            return

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

        self.send_json(
            200,
            response.model_dump()
        )

    # --------------------------------------------------
    # DELETE USER
    # --------------------------------------------------

    def do_DELETE(self):

        user_id = self.get_user_id()

        if user_id is None:
            return

        payload = self.authenticate_request(user_id)

        if payload is None:
            return

        user = get_user_by_id(user_id)

        if user is None:
            self.send_json(404, {
                "error": "User not found"
            })
            return

        delete_user(user_id)

        response = MessageResponse(
            message="User deleted successfully",
            id=user_id
        )

        self.send_json(
            200,
            response.model_dump()
        )


# --------------------------------------------------
# START SERVER
# --------------------------------------------------

server = HTTPServer(
    ("localhost", 8000),
    MyHandler
)

print("Server running on port 8000")

server.serve_forever()