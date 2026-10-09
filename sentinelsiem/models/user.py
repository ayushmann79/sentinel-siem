"""User and authentication models."""

from datetime import datetime
from enum import StrEnum
from pydantic import BaseModel, Field, EmailStr
import uuid


class Role(StrEnum):
    ADMIN    = "admin"
    ANALYST  = "analyst"
    READONLY = "readonly"


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str
    password: str = Field(..., min_length=8)
    role: Role = Role.ANALYST


class UserOut(BaseModel):
    id: str
    username: str
    email: str
    role: Role
    is_active: bool
    created_at: datetime
    last_login: datetime | None = None


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenPayload(BaseModel):
    sub: str          # username
    role: str
    exp: int
    jti: str = Field(default_factory=lambda: str(uuid.uuid4()))
