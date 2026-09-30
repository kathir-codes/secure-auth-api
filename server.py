
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

from database import create_users_table
from auth_utils import verify_access_token

# Authentication routes
from routes.auth_routes import (
    handle_signup,
    handle_signin,
    handle_forgot_password,
    handle_reset_password
)

# User routes
from routes.user_routes import (
    handle_get_all_users,
    handle_get_user,
    handle_update_user,
    handle_update_user_partial,
    handle_delete_user
)


# INITIALIZE DATABASE
create_users_table()


class MyHandler(BaseHTTPRequestHandler):

    # REUSABLE METHODS
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

    # GET
    # --------------------------------------------------

    def do_GET(self):

        # GET ALL USERS
        if self.path == "/users":

            handle_get_all_users(self)
            return

        # GET USER BY ID
        if self.path.startswith("/users/"):

            handle_get_user(self)
            return

        # UNKNOWN URL
        self.send_json(404, {
            "error": "Not Found"
        })

    # POST
    # --------------------------------------------------

    def do_POST(self):

        # SIGNUP
        if self.path == "/signup":

            handle_signup(self)
            return

        # SIGNIN
        if self.path == "/signin":

            handle_signin(self)
            return

        # FORGOT PASSWORD
        if self.path == "/forgot-password":

            handle_forgot_password(self)
            return

        # RESET PASSWORD
        if self.path == "/reset-password":

            handle_reset_password(self)
            return

        # UNKNOWN URL
        self.send_json(404, {
            "error": "Not Found"
        })

    # PUT - FULL USER UPDATE
    # --------------------------------------------------

    def do_PUT(self):

        if self.path.startswith("/users/"):

            handle_update_user(self)
            return

        self.send_json(404, {
            "error": "Not Found"
        })

    # PATCH - PARTIAL USER UPDATE
    # --------------------------------------------------

    def do_PATCH(self):

        if self.path.startswith("/users/"):

            handle_update_user_partial(self)
            return

        self.send_json(404, {
            "error": "Not Found"
        })

    # DELETE USER
    # --------------------------------------------------

    def do_DELETE(self):

        if self.path.startswith("/users/"):

            handle_delete_user(self)
            return

        self.send_json(404, {
            "error": "Not Found"
        })


# START SERVER
# --------------------------------------------------

server = HTTPServer(
    ("localhost", 8000),
    MyHandler
)

print("Server running on port 8000")

server.serve_forever()