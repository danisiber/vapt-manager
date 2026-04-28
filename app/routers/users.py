from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.user import User, UserRole
from app.schemas.user import UserResponse, UserCreate, PasswordChange
from app.utils.security import verify_password, hash_password
from app.routers.auth import get_current_user

router = APIRouter(prefix="/api/users", tags=["users"])

def require_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Hanya admin yang bisa mengakses menu ini")
    return current_user

# List all users — admin only
@router.get("/", response_model=List[UserResponse])
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.query(User).order_by(User.id).all()

# Create user — admin only
@router.post("/", response_model=UserResponse, status_code=201)
def create_user(user_data: UserCreate, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    existing = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username atau email sudah digunakan")
    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        role=user_data.role
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

# Delete user — admin only
@router.delete("/{user_id}")
def delete_user(user_id: int, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User tidak ditemukan")
    if user.username == "admin":
        raise HTTPException(status_code=400, detail="Tidak bisa menghapus user admin")
    db.delete(user)
    db.commit()
    return {"message": "User berhasil dihapus"}

# Change password — all authenticated users (own password, admin can change any)
@router.post("/change-password")
def change_password(payload: PasswordChange, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Verify old password
    if not verify_password(payload.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Password lama salah")
    # Update
    current_user.hashed_password = hash_password(payload.new_password)
    db.commit()
    return {"message": "Password berhasil diubah"}
