from fastapi import FastAPI
from app.schemas import AdminLogin, AdminResponse
from app.auth import login_admin

app = FastAPI()


@app.get("/")
def read_root():
    return {"message": "Admin Login API"}


@app.post("/login", response_model=AdminResponse)
def login(data: AdminLogin):
    return login_admin(data)
