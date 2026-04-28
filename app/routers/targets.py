from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.target import Target
from app.models.user import User
from app.routers.auth import get_current_user
from pydantic import BaseModel

router = APIRouter(prefix="/api/targets", tags=["targets"])

class TargetCreate(BaseModel):
    project_id: int
    name: str
    target_type: str
    url: str = None
    ip_address: str = None
    owner: str = None
    description: str = None

@router.get("/project/{project_id}")
def list_targets(project_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(Target).filter(Target.project_id == project_id).all()

@router.post("/")
def create_target(target: TargetCreate, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    db_target = Target(**target.model_dump())
    db.add(db_target)
    db.commit()
    db.refresh(db_target)
    return db_target

@router.delete("/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(target)
    db.commit()
    return {"message": "Target deleted"}
