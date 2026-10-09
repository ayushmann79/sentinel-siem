"""Authentication endpoints — login, refresh, user management."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from sentinelsiem.api.middleware.auth import (
    create_access_token, create_refresh_token,
    get_current_user, hash_password, require_admin, verify_password,
)
from sentinelsiem.config import get_settings
from sentinelsiem.database.connection import get_db
from sentinelsiem.models.user import Role, TokenPair, TokenPayload, UserCreate, UserOut

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()


class LoginIn(BaseModel):
    username: str
    password: str


@router.post("/login", response_model=TokenPair)
def login(body: LoginIn):
    with get_db() as db:
        row = db.execute(
            "SELECT id, username, password_hash, role, is_active FROM users WHERE username = ?",
            [body.username],
        ).fetchone()

    if not row or not verify_password(body.password, row[2]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not row[4]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")

    # Update last login
    with get_db() as db:
        db.execute("UPDATE users SET last_login = ? WHERE id = ?", [datetime.now(timezone.utc), row[0]])

    return TokenPair(
        access_token=create_access_token(row[1], row[3]),
        refresh_token=create_refresh_token(row[1], row[3]),
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/refresh", response_model=TokenPair)
def refresh(body: BaseModel):
    # Simplified — decode refresh token and issue new access token
    # In production: validate jti against a revocation store
    raise HTTPException(status_code=501, detail="Not implemented in this example")


@router.get("/me", response_model=UserOut)
def me(user: TokenPayload = Depends(get_current_user)):
    with get_db() as db:
        row = db.execute(
            "SELECT id, username, email, role, is_active, created_at, last_login FROM users WHERE username = ?",
            [user.sub],
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    return UserOut(
        id=row[0], username=row[1], email=row[2], role=row[3],
        is_active=row[4], created_at=row[5], last_login=row[6],
    )


@router.post("/users", response_model=UserOut, dependencies=[Depends(require_admin)])
def create_user(body: UserCreate):
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO users (id, created_at, username, email, password_hash, role) VALUES (?,?,?,?,?,?)",
                [user_id, now, body.username, body.email, hash_password(body.password), body.role.value],
            )
    except Exception as exc:
        raise HTTPException(status_code=409, detail="Username or email already exists") from exc

    return UserOut(
        id=user_id, username=body.username, email=body.email,
        role=body.role, is_active=True, created_at=now,
    )
