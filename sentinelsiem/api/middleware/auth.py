"""JWT verification and role-based access control helpers."""

from datetime import datetime, timedelta, timezone
from functools import wraps

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from sentinelsiem.config import get_settings
from sentinelsiem.models.user import Role, TokenPayload

_bearer = HTTPBearer()
_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
settings = get_settings()


# ── Password hashing ──────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return _pwd_ctx.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_ctx.verify(plain, hashed)


# ── Token creation ────────────────────────────────────────────────────────────

def create_access_token(username: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    return jwt.encode(
        {"sub": username, "role": role, "exp": expire, "type": "access"},
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )


def create_refresh_token(username: str, role: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
    return jwt.encode(
        {"sub": username, "role": role, "exp": expire, "type": "refresh"},
        settings.secret_key,
        algorithm=settings.jwt_algorithm,
    )


# ── Token verification ────────────────────────────────────────────────────────

def _decode(token: str) -> TokenPayload:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
        return TokenPayload(**payload)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(_bearer)) -> TokenPayload:
    return _decode(credentials.credentials)


def require_role(*roles: Role):
    """Dependency factory — raises 403 if user role not in allowed set."""
    def _dep(user: TokenPayload = Depends(get_current_user)) -> TokenPayload:
        if user.role not in [r.value for r in roles]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user
    return _dep


require_admin   = require_role(Role.ADMIN)
require_analyst = require_role(Role.ADMIN, Role.ANALYST)
require_any     = require_role(Role.ADMIN, Role.ANALYST, Role.READONLY)
