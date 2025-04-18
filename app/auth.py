from passlib.hash import bcrypt
from app.database import supabase
from app.schemas import AdminLogin, AdminResponse


def login_admin(data: AdminLogin) -> AdminResponse:
    response = supabase.table("admins").select("*").eq("username", data.username).execute()
    if response.data:
        admin = response.data[0]
        if bcrypt.verify(data.password, admin["password"]):
            return AdminResponse(success=True, admin_id=admin["id"], message="Login berhasil")
    return AdminResponse(success=False, admin_id=None, message="Username atau password salah")
