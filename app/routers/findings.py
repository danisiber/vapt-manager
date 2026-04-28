from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.finding import Finding
from app.models.user import User
from app.schemas.finding import FindingCreate, FindingUpdate, FindingResponse
from app.routers.auth import get_current_user

router = APIRouter(prefix="/api/findings", tags=["findings"])

@router.get("/project/{project_id}", response_model=List[FindingResponse])
def list_findings(project_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(Finding).filter(Finding.project_id == project_id).order_by(Finding.severity).all()

@router.post("/", response_model=FindingResponse)
def create_finding(finding: FindingCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_finding = Finding(**finding.model_dump(), created_by=current_user.id)
    db.add(db_finding)
    db.commit()
    db.refresh(db_finding)
    return db_finding

@router.put("/{finding_id}", response_model=FindingResponse)
def update_finding(finding_id: int, update: FindingUpdate, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    for key, value in update.model_dump(exclude_unset=True).items():
        setattr(finding, key, value)
    db.commit()
    db.refresh(finding)
    return finding

@router.patch("/{finding_id}", response_model=FindingResponse)
def patch_finding(finding_id: int, update: FindingUpdate, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    for key, value in update.model_dump(exclude_unset=True).items():
        setattr(finding, key, value)
    db.commit()
    db.refresh(finding)
    return finding

@router.delete("/{finding_id}")
def delete_finding(finding_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.delete(finding)
    db.commit()
    return {"message": "Finding deleted"}
