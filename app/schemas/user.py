from pydantic import BaseModel
from datetime import date, datetime
from typing import Optional

class UserBase(BaseModel):
    username: str
    email: str
    role: str

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int
    is_active: int
    created_at: Optional[datetime]
    class Config:
        from_attributes = True

class PasswordChange(BaseModel):
    old_password: str
    new_password: str
