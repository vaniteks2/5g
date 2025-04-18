from pydantic import BaseModel


class AdminLogin(BaseModel):
    username: str
    password: str


class AdminResponse(BaseModel):
    success: bool
    admin_id: str | None = None
    message: str
