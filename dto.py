from pydantic import BaseModel, ConfigDict


# ==========================================================
# REQUEST DTOs
# ==========================================================

class SignupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    email: str
    password: str


class SigninRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str
    password: str


class UpdateUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    email: str


class PartialUpdateUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    email: str | None = None


# ==========================================================
# RESPONSE DTOs
# ==========================================================

class SignupResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str
    id: int
    name: str
    email: str


class SigninResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str
    id: int
    name: str
    email: str
    access_token: str


class UserResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: int
    name: str
    email: str


class MessageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str
    id: int

class UserUpdateResponse(BaseModel):
    message: str
    id: int
    name: str
    email: str  

# ==========================================================
# PASSWORD RESET DTOs
# ==========================================================

class ForgotPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str


class ResetPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str
    new_password: str
    user_id: int