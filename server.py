
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

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
from pydantic import ValidationError
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
from auth_utils import hash_password, create_access_token,verify_access_token,create_password_reset_token, verify_password_reset_token
   


create_users_table()


class MyHandler(BaseHTTPRequestHandler):
# ----------------------------------------------------------------------------------
    def authenticate_request(self, requested_user_id=None):

        # Step 1: Get Authorization header
        authorization = self.headers.get("Authorization")

        if authorization is None:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                b'{"error": "Authorization header is required"}'
            )
            return None

        # Step 2: Check Bearer format
        if not authorization.startswith("Bearer "):
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                b'{"error": "Invalid authorization format"}'
            )
            return None

        # Step 3: Extract token
        token = authorization.split(" ", 1)[1].strip()

        # Step 4: Verify token
        payload = verify_access_token(token)

        if payload is None:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                b'{"error": "Invalid or expired token"}'
            )
            return None

        # Step 5: Verify ownership
        if requested_user_id is not None:

            logged_in_user_id = payload["user_id"]

            if logged_in_user_id != requested_user_id:
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    b'{"error": "Access denied"}'
                )
                return None

        # Step 6: Return payload
        return payload

    # -----------------------------------------------------------------------------------

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

            response_data = json.dumps(response).encode()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(response_data)

            return

        # GET USER BY ID
        if self.path.startswith("/users/"):

            user_id = int(self.path.split("/")[-1])

            user = get_user_by_id(user_id)

            if user is None:

                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()

                self.wfile.write(
                    b'{"error": "User not found"}'
                )

                return

            response = UserResponse(
                id=user[0],
                name=user[1],
                email=user[2]
            )

            response_data = json.dumps(
                response.model_dump()
            ).encode()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(response_data)

            return

        # UNKNOWN URL
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        self.wfile.write(
            b'{"error": "Not Found"}'
        )
    # -----------------------------------------------------------------------------------


    def do_POST(self):

        # ==========================================================
        # 1. SIGNIN
        # ==========================================================
       
        if self.path == "/signin":

            # Read the data sent by the client

            content_length = int(
                self.headers["Content-Length"]
            )

            body = self.rfile.read(content_length)

            # Convert JSON bytes into Python dictionary

            data = json.loads(body)

            # Validate request using Pydantic DTO

            try:
                signin_request = SigninRequest(**data)

            except ValidationError:

                self.send_response(400)

                self.send_header(
                    "Content-Type",
                    "application/json"
                )

                self.end_headers()

                self.wfile.write(
                    b'{"error": "Email and password are required"}'
                )

                return

            # Get user by email

            user = get_user_by_email(
                signin_request.email
            )

            # Check whether user exists

            if user is None:

                self.send_response(401)

                self.send_header(
                    "Content-Type",
                    "application/json"
                )

                self.end_headers()

                self.wfile.write(
                    b'{"error": "Invalid email or password"}'
                )

                return

            # Hash the entered password

            password_hash = hash_password(
                signin_request.password
            )

            # Compare passwords

            if password_hash != user[3]:

                self.send_response(401)

                self.send_header(
                    "Content-Type",
                    "application/json"
                )

                self.end_headers()

                self.wfile.write(
                    b'{"error": "Invalid email or password"}'
                )

                return

            # Login successful

            token = create_access_token(user[0])

            # Create response DTO

            response = SigninResponse(
                message="Signin successful",
                id=user[0],
                name=user[1],
                email=user[2],
                access_token=token
            )

            # Convert Pydantic object into JSON bytes

            response_data = json.dumps(
                response.model_dump()
            ).encode()

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(response_data)

            return


        # ==========================================================
        # 2. SIGNUP
        # ==========================================================

        if self.path == "/signup":

            # Read the data sent by the client

            content_length = int(
                self.headers["Content-Length"]
            )

            body = self.rfile.read(content_length)

            # Convert JSON bytes into Python dictionary

            data = json.loads(body)

            # Validate request using Pydantic DTO

            try:
                signup_request = SignupRequest(**data)

            except ValidationError:

                self.send_response(400)

                self.send_header(
                    "Content-Type",
                    "application/json"
                )

                self.end_headers()

                self.wfile.write(
                    b'{"error": "Name, email and password are required"}'
                )

                return

            # Hash the password

            password_hash = hash_password(
                signup_request.password
            )

            # Create user in database

            user_id = create_signup_user(
                signup_request.name,
                signup_request.email,
                password_hash
            )

            # Create response DTO

            response = SignupResponse(
                message="User signed up successfully",
                id=user_id,
                name=signup_request.name,
                email=signup_request.email
            )

            # Convert Pydantic object into JSON bytes

            response_data = json.dumps(
                response.model_dump()
            ).encode()

            # Send status

            self.send_response(201)

            # Send response header

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            # Send response body

            self.wfile.write(response_data)

            return
        
        # ==========================================================
        # 3. FORGOT PASSWORD
        # ==========================================================

        if self.path == "/forgot-password":


            # Read the data sent by the client

            content_length = int(
                self.headers["Content-Length"]
            )

            body = self.rfile.read(content_length)

            # Convert JSON bytes into Python dictionary

            data = json.loads(body)

            # Validate request using Pydantic DTO

            try:
                forgot_request = ForgotPasswordRequest(**data)

            except ValidationError:

                self.send_response(400)

                self.send_header(
                    "Content-Type",
                    "application/json"
                )

                self.end_headers()

                self.wfile.write(
                    b'{"error": "Email is required"}'
                )

                return

            # Find user by email

            user = get_user_by_email(
                forgot_request.email
            )

            # Generate reset token if user exists

            if user is not None:

                reset_token = create_password_reset_token(
                    user[0]
                )

                # Development only: print token in server console

                print("Password reset token:", reset_token)

            # Send generic response

            response_data = json.dumps({
                "message": "If the account exists, a password reset link has been sent."
            }).encode()

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(response_data)

            return
    
        # ==========================================================
        # 4. RESET PASSWORD
        # ==========================================================

        if self.path == "/reset-password":

            # Read request body

            content_length = int(
                self.headers["Content-Length"]
            )

            body = self.rfile.read(content_length)

            # Convert JSON into Python dictionary

            data = json.loads(body)

            # Validate request using Pydantic DTO

            try:
                reset_request = ResetPasswordRequest(**data)

            except ValidationError:

                self.send_response(400)

                self.send_header(
                    "Content-Type",
                    "application/json"
                )

                self.end_headers()

                self.wfile.write(
                    b'{"error": "Token and new password are required"}'
                )

                return

            # Verify reset token

            payload = verify_password_reset_token(
                reset_request.token,
                reset_request.user_id
        )

            # Check whether token is valid

            if payload is None:

                self.send_response(401)

                self.send_header(
                    "Content-Type",
                    "application/json"
                )

                self.end_headers()

                self.wfile.write(
                    b'{"error": "Invalid or expired reset token"}'
                )

                return

            # Get user ID from token

            user_id = payload["user_id"]

            # Hash the new password

            password_hash = hash_password(
                reset_request.new_password
            )

            # Update password in database

            update_user_password(
                user_id,
                password_hash
            )

            # Send success response

            response_data = json.dumps({
                "message": "Password reset successfully"
            }).encode()

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(response_data)

            return

        # ==========================================================
        # 3. UNKNOWN POST URL
        # ==========================================================

        self.send_response(404)

        self.send_header(
            "Content-Type",
            "application/json"
        )

        self.end_headers()

        self.wfile.write(
            b'{"error": "Not Found"}'
        )

    # -----------------------------------------------------------------------------------

    def do_PUT(self):

        # Get user ID from URL
        user_id = int(self.path.split("/")[-1])

        # Authenticate request
        payload = self.authenticate_request(user_id)

        if payload is None:
            return

        # Check whether user exists
        user = get_user_by_id(user_id)

        if user is None:

            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(
                b'{"error": "User not found"}'
            )

            return

        # Read request body
        content_length = int(self.headers["Content-Length"])
        body = self.rfile.read(content_length)

        data = json.loads(body)

        # Validate request using Pydantic DTO
        try:
            update_request = UpdateUserRequest(**data)

        except ValidationError:

            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(
                b'{"error": "Name and email are required"}'
            )

            return

        # Update user in database
        update_user(
            user_id,
            update_request.name,
            update_request.email
        )

        # Create response DTO
        response = UserUpdateResponse(
            message="User updated successfully",
            id=user_id,
            name=update_request.name,
            email=update_request.email
        )

        response_data = json.dumps(
            response.model_dump()
        ).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        self.wfile.write(response_data)

    # -----------------------------------------------------------------------------------

    def do_PATCH(self):

        # Get user ID from URL
        user_id = int(self.path.split("/")[-1])

        # Authenticate request
        payload = self.authenticate_request(user_id)

        if payload is None:
            return

        # Check whether user exists
        user = get_user_by_id(user_id)

        if user is None:

            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(
                b'{"error": "User not found"}'
            )

            return

        # Read request body
        content_length = int(self.headers["Content-Length"])
        body = self.rfile.read(content_length)

        data = json.loads(body)

        # Validate request using Pydantic DTO
        try:
            update_request = PartialUpdateUserRequest(**data)

        except ValidationError:

            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(
                b'{"error": "Invalid request data"}'
            )

            return

        # Get only the fields sent by the client
        update_data = update_request.model_dump(
            exclude_unset=True      #--> Field provided → Keep it.
        )                           #--> Field not provided → Exclude it.

        # Check whether at least one field is provided
        if not update_data:

            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(
                b'{"error": "Name or email is required"}'
            )

            return

        # Update user partially
        update_user_partial(
            user_id,
            update_data.get("name"),
            update_data.get("email")
        )

        # Get updated user data
        updated_user = get_user_by_id(user_id)

        # Create response DTO
        response = UserUpdateResponse(
            message="User partially updated",
            id=updated_user[0],
            name=updated_user[1],
            email=updated_user[2]
        )

        response_data = json.dumps(
            response.model_dump()
        ).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        self.wfile.write(response_data)

    # -----------------------------------------------------------------------------------

    def do_DELETE(self):

        # Get user ID from URL
        user_id = int(self.path.split("/")[-1])

        # Authenticate request
        payload = self.authenticate_request(user_id)

        if payload is None:
            return

        # Check whether user exists
        user = get_user_by_id(user_id)

        if user is None:

            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(
                b'{"error": "User not found"}'
            )

            return

        # Delete user
        delete_user(user_id)

        # Create response DTO
        response = MessageResponse(
            message="User deleted successfully",
            id=user_id
        )

        response_data = json.dumps(
            response.model_dump()
        ).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        self.wfile.write(response_data)


# -----------------------------------------------------------------------------------

server = HTTPServer(
    ("localhost", 8000),
    MyHandler
)

# -----------------------------------------------------------------------------------

print("Server running on port 8000")

server.serve_forever()