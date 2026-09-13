# ─────────────────────────────────────────────
#  routers/auth.py
#  User authentication endpoints (JWT).
#
#  ENDPOINTS:
#    POST /api/auth/register  — create a new analyst account
#    POST /api/auth/login     — log in and receive a JWT token
#    GET  /api/auth/me        — get current user info (requires token)
#
#  WHY JWT:
#  JWT (JSON Web Token) is a compact, self-contained way
#  to transmit user identity. After login, the server issues
#  a signed token. The client stores it and sends it with
#  every request in the Authorization header. The server
#  verifies the signature without touching the database.
#
#  For Phase 1, authentication is simple — one admin user
#  seeded directly. Full user management comes later.
# ─────────────────────────────────────────────
import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from pydantic import BaseModel
from dotenv import load_dotenv

from database.connection import get_db

load_dotenv()

router  = APIRouter(prefix="/api/auth", tags=["Authentication"])
bearer  = HTTPBearer()
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET    = os.getenv("JWT_SECRET", "change_this_secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE    = int(os.getenv("JWT_EXPIRE_MINUTES", "1440"))


# ── Pydantic models (request/response shapes) ─

class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username: str
    password: str
    full_name: str = ""


# ── Helpers ───────────────────────────────────

def _hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)

def _verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def _create_token(username: str) -> str:
    """
    Creates a signed JWT token that expires after JWT_EXPIRE minutes.
    The token encodes the username and expiry time.
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> str:
    """
    Dependency used by protected routes.
    Validates the JWT token and returns the username.

    Usage in a route:
      async def my_route(user: str = Depends(get_current_user)):
          ...
    """
    token = credentials.credentials
    try:
        payload  = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise ValueError("No subject in token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired.")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {e}")


# ── Endpoints ─────────────────────────────────

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest):
    """Register a new analyst account."""
    db = get_db()
    if db.users.find_one({"username": req.username}):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists.",
        )
    db.users.insert_one({
        "username":   req.username,
        "password":   _hash_password(req.password),
        "full_name":  req.full_name,
        "role":       "analyst",
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"message": "Account created successfully.", "username": req.username}


@router.post("/login")
async def login(req: LoginRequest):
    """
    Log in and receive a JWT access token.

    The frontend stores this token and includes it in all
    subsequent requests as: Authorization: Bearer <token>
    """
    db   = get_db()
    user = db.users.find_one({"username": req.username})
    if not user or not _verify_password(req.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )
    token = _create_token(req.username)
    return {
        "access_token": token,
        "token_type":   "bearer",
        "username":     req.username,
        "full_name":    user.get("full_name", ""),
    }


@router.get("/me")
async def get_me(username: str = Depends(get_current_user)):
    """Returns information about the currently logged-in user."""
    db   = get_db()
    user = db.users.find_one({"username": username}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return user
