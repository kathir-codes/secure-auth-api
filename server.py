
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

from database import (
    create_users_table,
    get_all_users,
    get_user_by_email,
    get_user_by_id,
    update_user,
    update_user_partial,
    delete_user,
    create_signup_user
)

from auth_utils import hash_password, create_access_token,verify_access_token


create_users_table()


class MyHandler(BaseHTTPRequestHandler):

    # -----------------------------------------------------------------------------------

    def do_GET(self):

        if self.path == "/users":

            users = get_all_users()

            response = []

            for user in users:

                response.append({
                    "id": user[0],
                    "name": user[1],
                    "email": user[2]
                })

            response_data = json.dumps(response).encode()

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(response_data)

            return

        # Check whether the requested path is for a user

        if self.path.startswith("/users/"):

            # Get user ID from URL

            user_id = int(
                self.path.split("/")[-1]
            )

            user = get_user_by_id(user_id)

            # Check whether user exists

            if user is None:

                self.send_response(404)

                self.send_header(
                    "Content-Type",
                    "application/json"
                )

                self.end_headers()

                self.wfile.write(
                    b'{"error": "User not found"}'
                )

                return

            # Get user data

            response = {
                "id": user[0],
                "name": user[1],
                "email": user[2]
            }

            # Convert dictionary into JSON bytes

            response_data = json.dumps(
                response
            ).encode()

            # Send success response

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(response_data)

            return

        # Handle unknown paths

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

            # Check required fields

            if (
                "email" not in data
                or "password" not in data
            ):

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
                data["email"]
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
                data["password"]
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
            response = {
                "message": "Signin successful",
                "id": user[0],
                "name": user[1],
                "email": user[2],
                "access_token": token
            }

            response_data = json.dumps(
                response
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

            # Check whether required fields exist

            if (
                "name" not in data
                or "email" not in data
                or "password" not in data
            ):

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
                data["password"]
            )

            # Create user in database

            user_id = create_signup_user(
                data["name"],
                data["email"],
                password_hash
            )

            # Create response

            response = {
                "message": "User signed up successfully",
                "id": user_id,
                "name": data["name"],
                "email": data["email"]
            }

            # Convert response to JSON bytes

            response_data = json.dumps(
                response
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

        user_id = int(
            self.path.split("/")[-1]
        )

        user = get_user_by_id(user_id)

        if user is None:

            self.send_response(404)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(
                b'{"error": "User not found"}'
            )

            return

        content_length = int(
            self.headers["Content-Length"]
        )

        body = self.rfile.read(content_length)

        data = json.loads(body)

        # Check whether name and email exist

        if (
            "name" not in data
            or "email" not in data
        ):

            self.send_response(400)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(
                b'{"error": "Name and email are required"}'
            )

            return

        # Update user

        update_user(
            user_id,
            data["name"],
            data["email"]
        )

        response = {
            "message": "User updated successfully",
            "id": user_id,
            "name": data["name"],
            "email": data["email"]
        }

        response_data = json.dumps(
            response
        ).encode()

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "application/json"
        )

        self.end_headers()

        self.wfile.write(response_data)

    # -----------------------------------------------------------------------------------

    def do_PATCH(self):

        # Get user ID from URL

        user_id = int(
            self.path.split("/")[-1]
        )

        user = get_user_by_id(user_id)

        # Check whether user exists

        if user is None:

            self.send_response(404)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(
                b'{"error": "User not found"}'
            )

            return

        # Read the data sent by the client

        content_length = int(
            self.headers["Content-Length"]
        )

        body = self.rfile.read(content_length)

        # Convert JSON bytes into Python dictionary

        data = json.loads(body)

        # Check whether at least one field is provided

        if (
            "name" not in data
            and "email" not in data
        ):

            self.send_response(400)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(
                b'{"error": "Name or email is required"}'
            )

            return

        # Update user partially

        update_user_partial(
            user_id,
            data.get("name"),
            data.get("email")
        )

        # Get updated user data

        updated_user = get_user_by_id(user_id)

        response = {
            "message": "User partially updated",
            "id": updated_user[0],
            "name": updated_user[1],
            "email": updated_user[2]
        }

        # Convert response into JSON bytes

        response_data = json.dumps(
            response
        ).encode()

        # Send success status

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "application/json"
        )

        self.end_headers()

        # Send response body

        self.wfile.write(response_data)

    # -----------------------------------------------------------------------------------

    def do_DELETE(self):

        # Get user ID from URL

        user_id = int(
            self.path.split("/")[-1]
        )

        user = get_user_by_id(user_id)

        # Check whether user exists

        if user is None:

            self.send_response(404)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.end_headers()

            self.wfile.write(
                b'{"error": "User not found"}'
            )

            return

        # Delete the user

        delete_user(user_id)

        # Create response

        response = {
            "message": "User deleted successfully",
            "id": user_id
        }

        # Convert response into JSON bytes

        response_data = json.dumps(
            response
        ).encode()

        # Send success status

        self.send_response(200)

        self.send_header(
            "Content-Type",
            "application/json"
        )

        self.end_headers()

        # Send response body

        self.wfile.write(response_data)


# -----------------------------------------------------------------------------------

server = HTTPServer(
    ("localhost", 8000),
    MyHandler
)

# -----------------------------------------------------------------------------------

print("Server running on port 8000")

server.serve_forever()