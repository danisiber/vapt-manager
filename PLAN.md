# VAPT Project Management — Implementation Plan

> **Goal:** Build a web-based VAPT (Vulnerability Assessment & Penetration Testing) project management system for Bank Kalbar's cybersecurity team.
> Manage pentest projects, display vulnerabilities per project, and generate PDF reports.

**Aesthetic Direction:** Dark mode cybersecurity theme — bold, distinctive, NOT generic AI slop.
- Background: Deep charcoal/near-black (#0d0d0d, #111827)
- Accent: Cyber green (#00ff88) or amber (#ffb800) on dark
- Typography: JetBrains Mono (headers/code feel) + Inter or Satoshi (body)
- Motion: Subtle glow, staggered reveals, hover micro-interactions
- Feel: Professional SOC/dashboard aesthetic with premium polish

**Architecture:** FastAPI backend + SQLite + TailwindCSS dark theme + ReportLab PDF

**Tech Stack:** Python 3, FastAPI, SQLite (via SQLAlchemy), TailwindCSS (dark), ReportLab, Jinja2

---

## Phase 1: Project Structure + Requirements

### Task 1: Initialize Project + requirements.txt

**Create:** `~/pentest-manager/requirements.txt`

```txt
fastapi==0.109.0
uvicorn[standard]==0.27.0
sqlalchemy==2.0.25
pydantic==2.5.3
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6
reportlab==4.1.0
jinja2==3.1.3
aiofiles==23.2.1
pydantic-settings==2.1.0
```

**Create:** `~/pentest-manager/run.py`

```python
import uvicorn
import sys
sys.path.insert(0, '/root/pentest-manager')
from app.main import app

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
```

---

### Task 2: App Config + Database

**Create:** `~/pentest-manager/app/__init__.py` (empty)

**Create:** `~/pentest-manager/app/config.py`

```python
from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    APP_NAME: str = "VAPT Manager — Bank Kalbar"
    SECRET_KEY: str = "bank-kalbar-vapt-secret-key-2026-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480

    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()
```

**Create:** `~/pentest-manager/app/database.py`

```python
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./vapt_manager.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
```

---

### Task 3: Security Utils (Password + JWT)

**Create:** `~/pentest-manager/app/utils/__init__.py` (empty)
**Create:** `~/pentest-manager/app/utils/security.py`

```python
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, secret: str, minutes: int = 480) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret, algorithm="HS256")

def decode_token(token: str, secret: str):
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except JWTError:
        return None
```

---

## Phase 2: Models

### Task 4: User Model

**Create:** `~/pentest-manager/app/models/__init__.py` (empty)
**Create:** `~/pentest-manager/app/models/user.py`

```python
from sqlalchemy import Column, Integer, String, DateTime, Enum
from sqlalchemy.sql import func
from app.database import Base
import enum

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    PENTESTER = "pentester"
    VIEWER = "viewer"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.PENTESTER)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_active = Column(Integer, default=1)
```

---

### Task 5: Project Model (with start_date + end_date)

**Create:** `~/pentest-manager/app/models/project.py`

```python
from sqlalchemy import Column, Integer, String, Text, Date, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import enum

class ProjectStatus(str, enum.Enum):
    PLANNING = "planning"
    IN_PROGRESS = "in_progress"
    ON_HOLD = "on_hold"
    COMPLETED = "completed"

class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    status = Column(Enum(ProjectStatus), default=ProjectStatus.PLANNING)
    start_date = Column(Date, nullable=False)          # ← REQUIRED
    end_date = Column(Date, nullable=False)           # ← REQUIRED
    scope = Column(Text, nullable=True)                # e.g., "Internet Banking, Mobile App"
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True, onupdate=func.now()))

    targets = relationship("Target", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")
    creator = relationship("User", foreign_keys=[created_by])
```

---

### Task 6: Target Model

**Create:** `~/pentest-manager/app/models/target.py`

```python
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base

class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    name = Column(String(200), nullable=False)         # e.g., "Internet Banking"
    target_type = Column(String(50), nullable=False)   # web, mobile, api, network, api
    url = Column(String(500), nullable=True)
    ip_address = Column(String(50), nullable=True)
    owner = Column(String(100), nullable=True)         # internal contact
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    project = relationship("Project", back_populates="targets")
    findings = relationship("Finding", back_populates="target", cascade="all, delete-orphan")
```

---

### Task 7: Finding Model (Vulnerability)

**Create:** `~/pentest-manager/app/models/finding.py`

```python
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import enum

class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"

class FindingStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    title = Column(String(300), nullable=False)
    severity = Column(Enum(Severity), default=Severity.MEDIUM)
    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN)
    cve_id = Column(String(50), nullable=True)
    cvss_score = Column(Float, nullable=True)
    description = Column(Text, nullable=True)
    steps_to_reproduce = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True, onupdate=func.now()))

    project = relationship("Project", back_populates="findings")
    target = relationship("Target", back_populates="findings")
```

---

## Phase 3: Schemas (Pydantic)

### Task 8: Pydantic Schemas

**Create:** `~/pentest-manager/app/schemas/__init__.py` (empty)
**Create:** `~/pentest-manager/app/schemas/user.py`

```python
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
```

**Create:** `~/pentest-manager/app/schemas/project.py`

```python
from pydantic import BaseModel
from datetime import date, datetime
from typing import Optional, List

class ProjectBase(BaseModel):
    name: str
    description: Optional[str] = None
    scope: Optional[str] = None
    start_date: date
    end_date: date
    status: str = "planning"

class ProjectCreate(ProjectBase):
    pass

class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    scope: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    status: Optional[str] = None

class TargetResponse(BaseModel):
    id: int
    name: str
    target_type: str
    url: Optional[str]
    ip_address: Optional[str]
    owner: Optional[str]
    class Config:
        from_attributes = True

class FindingResponse(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    cve_id: Optional[str]
    cvss_score: Optional[float]
    class Config:
        from_attributes = True

class ProjectResponse(ProjectBase):
    id: int
    created_at: Optional[datetime]
    findings: List[FindingResponse] = []
    targets: List[TargetResponse] = []
    class Config:
        from_attributes = True
```

**Create:** `~/pentest-manager/app/schemas/finding.py`

```python
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class FindingBase(BaseModel):
    title: str
    severity: str = "medium"
    status: str = "open"
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    steps_to_reproduce: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    target_id: Optional[int] = None

class FindingCreate(FindingBase):
    project_id: int

class FindingUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    steps_to_reproduce: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    target_id: Optional[int] = None
    assigned_to: Optional[int] = None

class FindingResponse(FindingBase):
    id: int
    project_id: int
    target_id: Optional[int]
    created_at: Optional[datetime]
    class Config:
        from_attributes = True
```

---

## Phase 4: Routers (API)

### Task 9: Auth Router

**Create:** `~/pentest-manager/app/routers/__init__.py` (empty)
**Create:** `~/pentest-manager/app/routers/auth.py`

```python
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserResponse
from app.utils.security import verify_password, create_access_token, hash_password, decode_token
from app.config import get_settings

router = APIRouter(prefix="/auth", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")
settings = get_settings()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = decode_token(token, settings.SECRET_KEY)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.username == payload.get("sub")).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username, "role": user.role.value}, settings.SECRET_KEY)
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/register", response_model=UserResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
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
```

---

### Task 10: Projects Router

**Create:** `~/pentest-manager/app/routers/projects.py`

```python
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.project import Project
from app.models.user import User
from app.schemas.project import ProjectCreate, ProjectUpdate, ProjectResponse
from app.routers.auth import get_current_user

router = APIRouter(prefix="/api/projects", tags=["projects"])

@router.get("/", response_model=List[ProjectResponse])
def list_projects(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    projects = db.query(Project).order_by(Project.created_at.desc()).all()
    return projects

@router.post("/", response_model=ProjectResponse)
def create_project(project: ProjectCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_project = Project(**project.model_dump(), created_by=current_user.id)
    db.add(db_project)
    db.commit()
    db.refresh(db_project)
    return db_project

@router.get("/{project_id}", response_model=ProjectResponse)
def get_project(project_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project

@router.put("/{project_id}", response_model=ProjectResponse)
def update_project(project_id: int, update: ProjectUpdate, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    for key, value in update.model_dump(exclude_unset=True).items():
        setattr(project, key, value)
    db.commit()
    db.refresh(project)
    return project

@router.delete("/{project_id}")
def delete_project(project_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    db.delete(project)
    db.commit()
    return {"message": "Project deleted"}
```

---

### Task 11: Targets Router

**Create:** `~/pentest-manager/app/routers/targets.py`

```python
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.target import Target
from app.models.user import User
from app.routers.auth import get_current_user

router = APIRouter(prefix="/api/targets", tags=["targets"])

@router.get("/project/{project_id}")
def list_targets(project_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(Target).filter(Target.project_id == project_id).all()

@router.post("/")
def create_target(project_id: int, name: str, target_type: str, url: str = None,
                 ip_address: str = None, owner: str = None, description: str = None,
                 db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    target = Target(project_id=project_id, name=name, target_type=target_type,
                    url=url, ip_address=ip_address, owner=owner, description=description)
    db.add(target)
    db.commit()
    db.refresh(target)
    return target

@router.delete("/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(target)
    db.commit()
    return {"message": "Target deleted"}
```

---

### Task 12: Findings Router

**Create:** `~/pentest-manager/app/routers/findings.py`

```python
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

@router.delete("/{finding_id}")
def delete_finding(finding_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.delete(finding)
    db.commit()
    return {"message": "Finding deleted"}
```

---

## Phase 5: Report Generator

### Task 13: PDF Report Service

**Create:** `~/pentest-manager/app/services/__init__.py` (empty)
**Create:** `~/pentest-manager/app/services/report.py`

```python
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.finding import Severity

SEVERITY_COLORS_MAP = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#f97316"),
    "medium": colors.HexColor("#eab308"),
    "low": colors.HexColor("#3b82f6"),
    "informational": colors.HexColor("#6b7280"),
}

def generate_project_report(project_id: int, output_path: str) -> str:
    db = SessionLocal()
    from app.models.project import Project
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise ValueError(f"Project {project_id} not found")

    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=20, spaceAfter=12)
    heading_style = ParagraphStyle('CustomH1', parent=styles['Heading1'], fontSize=14, spaceAfter=8, spaceBefore=16)
    
    story = []
    
    # Cover
    story.append(Paragraph("VAPT REPORT", styles['Title']))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(f"Project: {project.name}", title_style))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(f"<b>Periode:</b> {project.start_date} s/d {project.end_date}", styles['Normal']))
    story.append(Paragraph(f"<b>Status:</b> {project.status.value.replace('_', ' ').title()}", styles['Normal']))
    if project.scope:
        story.append(Paragraph(f"<b>Scope:</b> {project.scope}", styles['Normal']))
    if project.description:
        story.append(Paragraph(f"<b>Deskripsi:</b> {project.description}", styles['Normal']))
    story.append(Spacer(1, 1*cm))

    # Findings Summary
    findings = sorted(project.findings, key=lambda f: ["critical","high","medium","low","informational"].index(f.severity.value))
    
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for f in project.findings:
        severity_counts[f.severity.value] += 1

    story.append(Paragraph("Ringkasan Temuan", heading_style))
    summary_data = [["Severity", "Jumlah"]]
    for sev, count in severity_counts.items():
        summary_data.append([sev.upper().replace("INFORMATIONAL", "INFO"), str(count)])
    
    t = Table(summary_data, colWidths=[8*cm, 4*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#374151")),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (0, 1), SEVERITY_COLORS_MAP.get("critical", colors.red)),
        ('BACKGROUND', (0, 2), (0, 2), SEVERITY_COLORS_MAP.get("high", colors.orange)),
        ('BACKGROUND', (0, 3), (0, 3), SEVERITY_COLORS_MAP.get("medium", colors.yellow)),
        ('BACKGROUND', (0, 4), (0, 4), SEVERITY_COLORS_MAP.get("low", colors.blue)),
        ('BACKGROUND', (0, 5), (0, 5), SEVERITY_COLORS_MAP.get("informational", colors.grey)),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.white),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
    ]))
    story.append(t)
    story.append(Spacer(1, 1*cm))

    # Detailed Findings
    if findings:
        story.append(Paragraph("Detail Temuan", heading_style))
        for i, f in enumerate(findings):
            story.append(PageBreak())
            sev_color = SEVERITY_COLORS_MAP.get(f.severity.value, colors.grey)
            
            # Finding header with severity badge
            header_data = [[
                Paragraph(f"<b>Finding #{i+1}: {f.title}</b>", styles['Normal']),
                Paragraph(f"<b>[{f.severity.value.upper()}]</b>", styles['Normal'])
            ]]
            ht = Table(header_data, colWidths=[12*cm, 4*cm])
            ht.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), sev_color),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
            ]))
            story.append(ht)
            story.append(Spacer(1, 0.3*cm))
            
            # Meta
            meta_text = f"Status: {f.status.value.replace('_',' ').title()}"
            if f.cve_id:
                meta_text += f" | CVE: {f.cve_id}"
            if f.cvss_score is not None:
                meta_text += f" | CVSS: {f.cvss_score}"
            story.append(Paragraph(meta_text, styles['Normal']))
            story.append(Spacer(1, 0.3*cm))
            
            for label, field in [("Deskripsi", f.description), ("Langkah Reproduksi", f.steps_to_reproduce),
                                   ("Dampak", f.impact), ("Remediasi", f.remediation)]:
                if field:
                    story.append(Paragraph(f"<b>{label}:</b>", styles['Normal']))
                    story.append(Paragraph(field, styles['Normal']))
                    story.append(Spacer(1, 0.2*cm))

    db.close()
    doc.build(story)
    return output_path
```

---

### Task 14: Reports Router

**Create:** `~/pentest-manager/app/routers/reports.py`

```python
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from app.services.report import generate_project_report
import tempfile, os

router = APIRouter(prefix="/api/reports", tags=["reports"])

@router.get("/project/{project_id}/pdf")
def download_report(project_id: int):
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        output_path = tmp.name
    try:
        path = generate_project_report(project_id, output_path)
        return FileResponse(path, media_type="application/pdf",
                          filename=f"vapt_report_project_{project_id}.pdf")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        if os.path.exists(output_path):
            os.unlink(output_path)
```

---

## Phase 6: FastAPI Main + Templates Init

### Task 15: Main App + Database Init

**Create:** `~/pentest-manager/app/main.py`

```python
from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.database import engine, get_db, Base
from app.models import user, project, target, finding
from app.routers import auth, projects, targets, findings, reports

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="VAPT Manager — Bank Kalbar", version="1.0.0")

# Include routers
app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(targets.router)
app.include_router(findings.router)
app.include_router(reports.router)

# Static + Templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Pages
@app.get("/", response_class=RedirectResponse)
def root():
    return "/login"

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/projects", response_class=HTMLResponse)
def projects_page(request: Request):
    return templates.TemplateResponse("projects.html", {"request": request})

@app.get("/projects/{project_id}", response_class=HTMLResponse)
def project_detail(request: Request, project_id: int):
    return templates.TemplateResponse("project_detail.html", {"request": request, "project_id": project_id})

# Seed admin on startup
@app.on_event("startup")
def seed_admin():
    db = next(get_db())
    from app.models.user import User, UserRole
    from app.utils.security import hash_password
    if not db.query(User).filter(User.username == "admin").first():
        admin = User(
            username="admin",
            email="admin@bankkalbar.co.id",
            hashed_password=hash_password("admin123"),
            role=UserRole.ADMIN
        )
        db.add(admin)
        db.commit()
```

---

## Phase 7: Frontend — Dark Mode UI (Using frontend-design principles)

### Task 16: Base Template (Dark Mode)

**Create directories:**
```
static/css/
static/js/
templates/
```

**Create:** `~/pentest-manager/templates/base.html`

```html
<!DOCTYPE html>
<html lang="id" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}VAPT Manager{% endblock %} — Bank Kalbar</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        mono: ['JetBrains Mono', 'monospace'],
                        sans: ['Inter', 'sans-serif'],
                    },
                    colors: {
                        cyber: {
                            50: '#f0fdf4',
                            100: '#dcfce7',
                            400: '#22c55e',
                            500: '#00ff88',
                            600: '#16a34a',
                            900: '#14532d',
                        },
                        dark: {
                            50: '#f8fafc',
                            100: '#f1f5f9',
                            200: '#e2e8f0',
                            800: '#1e293b',
                            900: '#0f172a',
                            950: '#020617',
                        }
                    }
                }
            }
        }
    </script>
    <style>
        body { font-family: 'Inter', sans-serif; background: #020617; color: #e2e8f0; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        
        /* Subtle grid background */
        .cyber-grid {
            background-image: 
                linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px);
            background-size: 40px 40px;
        }
        
        /* Glow effect */
        .glow-green { box-shadow: 0 0 20px rgba(0, 255, 136, 0.15); }
        .glow-green:hover { box-shadow: 0 0 30px rgba(0, 255, 136, 0.3); }
        
        /* Severity badges */
        .sev-critical { background: #dc2626; color: white; }
        .sev-high { background: #f97316; color: white; }
        .sev-medium { background: #eab308; color: black; }
        .sev-low { background: #3b82f6; color: white; }
        .sev-info { background: #6b7280; color: white; }
        
        /* Animations */
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .animate-in { animation: fadeInUp 0.4s ease-out forwards; }
        
        /* Scrollbar */
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0f172a; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
    </style>
    <script>
        const API_BASE = "/api";
        async function api(endpoint, options = {}) {
            const token = localStorage.getItem("token");
            const headers = { "Content-Type": "application/json" };
            if (token) headers["Authorization"] = `Bearer ${token}`;
            const res = await fetch(API_BASE + endpoint, { ...options, headers: { ...headers, ...options.headers } });
            if (res.status === 401) { localStorage.removeItem("token"); window.location.href = "/login"; throw new Error("Unauthorized"); }
            if (!res.ok) throw new Error(await res.text());
            return res.json();
        }
        
        function sevClass(severity) {
            const map = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low', informational: 'sev-info' };
            return map[severity] || 'sev-info';
        }
        
        function statusBadge(status) {
            const colors = {
                planning: 'bg-purple-900 text-purple-200',
                in_progress: 'bg-blue-900 text-blue-200',
                on_hold: 'bg-yellow-900 text-yellow-200',
                completed: 'bg-green-900 text-green-200',
                open: 'bg-red-900 text-red-200',
                resolved: 'bg-green-900 text-green-200',
                accepted: 'bg-gray-700 text-gray-200',
                false_positive: 'bg-gray-700 text-gray-200',
                in_progress: 'bg-blue-900 text-blue-200'
            };
            return colors[status] || 'bg-gray-700 text-gray-200';
        }
    </script>
</head>
<body class="min-h-screen cyber-grid">
    {% block content %}{% endblock %}
</body>
</html>
```

---

### Task 17: Login Page

**Create:** `~/pentest-manager/templates/login.html`

```html
{% extends "base.html" %}
{% block title %}Login{% endblock %}
{% block content %}
<div class="min-h-screen flex items-center justify-center px-4">
    <!-- Decorative glow -->
    <div class="absolute top-1/4 left-1/2 -translate-x-1/2 w-96 h-96 bg-cyber-500/5 rounded-full blur-3xl"></div>
    
    <div class="w-full max-w-md relative animate-in">
        <!-- Logo/Brand -->
        <div class="text-center mb-8">
            <div class="inline-flex items-center gap-3 mb-2">
                <div class="w-10 h-10 rounded-lg bg-cyber-500/20 border border-cyber-500/30 flex items-center justify-center">
                    <svg class="w-6 h-6 text-cyber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                    </svg>
                </div>
                <span class="font-mono text-xl font-bold text-white tracking-wider">VAPT<span class="text-cyber-400">Manager</span></span>
            </div>
            <p class="text-gray-500 text-sm font-mono">Bank Kalbar — Security Operations</p>
        </div>
        
        <!-- Login Card -->
        <div class="bg-dark-900 border border-gray-800 rounded-2xl p-8 glow-green">
            <h2 class="text-xl font-bold text-white mb-6 font-mono tracking-wide">Sign In</h2>
            
            <form id="loginForm" class="space-y-5">
                <div>
                    <label class="block text-sm text-gray-400 mb-2 font-mono text-xs uppercase tracking-wider">Username</label>
                    <input type="text" name="username" required
                        class="w-full bg-dark-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-cyber-500 focus:ring-1 focus:ring-cyber-500/50 transition-all font-mono"
                        placeholder="Enter username">
                </div>
                <div>
                    <label class="block text-sm text-gray-400 mb-2 font-mono text-xs uppercase tracking-wider">Password</label>
                    <input type="password" name="password" required
                        class="w-full bg-dark-800 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:border-cyber-500 focus:ring-1 focus:ring-cyber-500/50 transition-all font-mono"
                        placeholder="Enter password">
                </div>
                <button type="submit"
                    class="w-full bg-cyber-500 hover:bg-cyber-400 text-dark-900 font-bold py-3 rounded-lg transition-all duration-200 font-mono tracking-wide">
                    ACCESS SYSTEM
                </button>
            </form>
            
            <p id="error" class="text-red-400 mt-4 text-sm font-mono hidden"></p>
        </div>
        
        <p class="text-center text-gray-600 mt-6 text-xs font-mono">Bank Kalbar — Fungsi Ketahanan Keamanan Siber</p>
    </div>
</div>

<script>
document.getElementById("loginForm").onsubmit = async (e) => {
    e.preventDefault();
    const data = new FormData(e.target);
    const btn = e.target.querySelector('button');
    btn.textContent = "AUTHENTICATING...";
    btn.disabled = true;
    
    try {
        const res = await fetch("/auth/token", {
            method: "POST",
            body: new URLSearchParams({ username: data.get("username"), password: data.get("password") }),
            headers: { "Content-Type": "application/x-www-form-urlencoded" }
        });
        if (!res.ok) throw new Error("Invalid credentials");
        const json = await res.json();
        localStorage.setItem("token", json.access_token);
        window.location.href = "/dashboard";
    } catch(err) {
        document.getElementById("error").textContent = "> ACCESS DENIED — Check credentials";
        document.getElementById("error").classList.remove("hidden");
        btn.textContent = "ACCESS SYSTEM";
        btn.disabled = false;
    }
};
</script>
{% endblock %}
```

---

### Task 18: Dashboard Page

**Create:** `~/pentest-manager/templates/dashboard.html`

```html
{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}
{% block content %}
<!-- Navbar -->
<nav class="border-b border-gray-800 bg-dark-900/80 backdrop-blur-sm sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded bg-cyber-500/20 border border-cyber-500/30 flex items-center justify-center">
                <svg class="w-5 h-5 text-cyber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                </svg>
            </div>
            <span class="font-mono text-lg font-bold text-white">VAPT<span class="text-cyber-400">Manager</span></span>
        </div>
        <div class="flex items-center gap-4">
            <span class="text-gray-500 text-sm font-mono hidden sm:block">BANK KALBAR SECOPS</span>
            <a href="/login" onclick="localStorage.removeItem('token')" class="text-gray-400 hover:text-red-400 transition-colors text-sm font-mono">LOGOUT</a>
        </div>
    </div>
</nav>

<!-- Main Content -->
<main class="max-w-7xl mx-auto px-6 py-8">
    <!-- Header -->
    <div class="mb-8 animate-in">
        <h1 class="text-3xl font-bold text-white font-mono tracking-tight">Security Dashboard</h1>
        <p class="text-gray-500 mt-1 font-sans">VAPT Project Overview — Bank Kalbar</p>
    </div>
    
    <!-- Stats Grid -->
    <div class="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
        <div class="bg-dark-800 border border-gray-800 rounded-xl p-5 hover:border-cyber-500/30 transition-all animate-in" style="animation-delay:0.05s">
            <div class="text-gray-500 text-xs font-mono uppercase tracking-wider mb-2">Total Project</div>
            <div id="stat-projects" class="text-3xl font-bold font-mono text-white">—</div>
        </div>
        <div class="bg-dark-800 border border-gray-800 rounded-xl p-5 hover:border-cyber-500/30 transition-all animate-in" style="animation-delay:0.1s">
            <div class="text-gray-500 text-xs font-mono uppercase tracking-wider mb-2">Total Findings</div>
            <div id="stat-findings" class="text-3xl font-bold font-mono text-white">—</div>
        </div>
        <div class="bg-dark-800 border border-gray-800 rounded-xl p-5 hover:border-red-500/30 transition-all animate-in" style="animation-delay:0.15s">
            <div class="text-gray-500 text-xs font-mono uppercase tracking-wider mb-2">Critical</div>
            <div id="stat-critical" class="text-3xl font-bold font-mono text-red-400">—</div>
        </div>
        <div class="bg-dark-800 border border-gray-800 rounded-xl p-5 hover:border-orange-500/30 transition-all animate-in" style="animation-delay:0.2s">
            <div class="text-gray-500 text-xs font-mono uppercase tracking-wider mb-2">High</div>
            <div id="stat-high" class="text-3xl font-bold font-mono text-orange-400">—</div>
        </div>
        <div class="bg-dark-800 border border-gray-800 rounded-xl p-5 hover:border-cyber-500/30 transition-all animate-in" style="animation-delay:0.25s">
            <div class="text-gray-500 text-xs font-mono uppercase tracking-wider mb-2">Completed</div>
            <div id="stat-completed" class="text-3xl font-bold font-mono text-cyber-400">—</div>
        </div>
    </div>
    
    <!-- Projects Table -->
    <div class="bg-dark-800 border border-gray-800 rounded-xl overflow-hidden animate-in" style="animation-delay:0.3s">
        <div class="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
            <h2 class="font-mono font-semibold text-white">Recent VAPT Projects</h2>
            <a href="/projects" class="text-cyber-400 hover:text-cyber-300 text-sm font-mono transition-colors">View All →</a>
        </div>
        <div class="overflow-x-auto">
            <table class="w-full">
                <thead class="bg-dark-900">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-mono font-semibold text-gray-500 uppercase tracking-wider">Project</th>
                        <th class="px-6 py-3 text-left text-xs font-mono font-semibold text-gray-500 uppercase tracking-wider">Periode</th>
                        <th class="px-6 py-3 text-left text-xs font-mono font-semibold text-gray-500 uppercase tracking-wider">Status</th>
                        <th class="px-6 py-3 text-left text-xs font-mono font-semibold text-gray-500 uppercase tracking-wider">Findings</th>
                        <th class="px-6 py-3 text-left text-xs font-mono font-semibold text-gray-500 uppercase tracking-wider">Action</th>
                    </tr>
                </thead>
                <tbody id="projects-tbody" class="divide-y divide-gray-800"></tbody>
            </table>
        </div>
        <div id="empty-state" class="hidden px-6 py-12 text-center">
            <div class="text-gray-600 font-mono">No projects found. Create your first VAPT project.</div>
        </div>
    </div>
</main>

<script>
async function loadDashboard() {
    try {
        const projects = await api("/projects");
        
        let totalFindings = 0, critical = 0, high = 0, completed = 0;
        projects.forEach(p => {
            const findings = p.findings || [];
            totalFindings += findings.length;
            findings.forEach(f => {
                if (f.severity === 'critical') critical++;
                if (f.severity === 'high') high++;
            });
            if (p.status === 'completed') completed++;
        });
        
        document.getElementById("stat-projects").textContent = projects.length;
        document.getElementById("stat-findings").textContent = totalFindings;
        document.getElementById("stat-critical").textContent = critical;
        document.getElementById("stat-high").textContent = high;
        document.getElementById("stat-completed").textContent = completed;
        
        const tbody = document.getElementById("projects-tbody");
        if (projects.length === 0) {
            document.getElementById("empty-state").classList.remove("hidden");
            return;
        }
        
        projects.slice(0, 8).forEach((p, i) => {
            const findings = p.findings || [];
            const criticalCount = findings.filter(f => f.severity === 'critical').length;
            const highCount = findings.filter(f => f.severity === 'high').length;
            
            const row = document.createElement("tr");
            row.className = "hover:bg-dark-700/50 transition-colors";
            row.style.animationDelay = `${0.3 + i * 0.05}s`;
            row.innerHTML = `
                <td class="px-6 py-4">
                    <div class="font-semibold text-white font-mono text-sm">${p.name}</div>
                    <div class="text-gray-500 text-xs mt-0.5">${p.scope || 'No scope defined'}</div>
                </td>
                <td class="px-6 py-4">
                    <div class="text-gray-300 text-sm font-mono">${p.start_date}</div>
                    <div class="text-gray-600 text-xs">to ${p.end_date}</div>
                </td>
                <td class="px-6 py-4">
                    <span class="px-2.5 py-1 rounded-full text-xs font-mono font-semibold ${statusBadge(p.status)}">
                        ${p.status.replace('_',' ').toUpperCase()}
                    </span>
                </td>
                <td class="px-6 py-4">
                    <div class="flex gap-2 flex-wrap">
                        ${criticalCount > 0 ? `<span class="px-2 py-0.5 rounded text-xs font-mono bg-red-900/50 text-red-400 border border-red-800">${criticalCount}C</span>` : ''}
                        ${highCount > 0 ? `<span class="px-2 py-0.5 rounded text-xs font-mono bg-orange-900/50 text-orange-400 border border-orange-800">${highCount}H</span>` : ''}
                        <span class="px-2 py-0.5 rounded text-xs font-mono bg-dark-700 text-gray-400 border border-gray-700">${findings.length} total</span>
                    </div>
                </td>
                <td class="px-6 py-4">
                    <a href="/projects/${p.id}" class="text-cyber-400 hover:text-cyber-300 text-sm font-mono transition-colors">View →</a>
                </td>
            `;
            tbody.appendChild(row);
        });
    } catch(err) {
        console.error("Failed to load dashboard:", err);
    }
}

loadDashboard();
</script>
{% endblock %}
```

---

### Task 19: Projects List Page

**Create:** `~/pentest-manager/templates/projects.html`

```html
{% extends "base.html" %}
{% block title %}Projects{% endblock %}
{% block content %}
<nav class="border-b border-gray-800 bg-dark-900/80 backdrop-blur-sm sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded bg-cyber-500/20 border border-cyber-500/30 flex items-center justify-center">
                <svg class="w-5 h-5 text-cyber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                </svg>
            </div>
            <span class="font-mono text-lg font-bold text-white">VAPT<span class="text-cyber-400">Manager</span></span>
            <span class="text-gray-600">/</span>
            <span class="font-mono text-gray-400">Projects</span>
        </div>
        <div class="flex items-center gap-4">
            <a href="/dashboard" class="text-gray-400 hover:text-white transition-colors text-sm font-mono">← Dashboard</a>
        </div>
    </div>
</nav>

<main class="max-w-7xl mx-auto px-6 py-8">
    <div class="flex items-center justify-between mb-8">
        <div>
            <h1 class="text-3xl font-bold text-white font-mono tracking-tight">VAPT Projects</h1>
            <p class="text-gray-500 mt-1">Manage all penetration testing projects</p>
        </div>
        <button onclick="showCreateModal()" class="bg-cyber-500 hover:bg-cyber-400 text-dark-900 font-bold py-3 px-6 rounded-lg transition-all font-mono text-sm glow-green">
            + NEW PROJECT
        </button>
    </div>
    
    <!-- Projects Grid -->
    <div id="projects-grid" class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6"></div>
    <div id="empty-state" class="hidden text-center py-16">
        <div class="text-gray-600 font-mono text-lg mb-2">No projects yet</div>
        <div class="text-gray-700 text-sm">Create your first VAPT project to get started</div>
    </div>
</main>

<!-- Create Project Modal -->
<div id="create-modal" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden items-center justify-center p-4">
    <div class="bg-dark-800 border border-gray-700 rounded-2xl w-full max-w-lg p-8">
        <h2 class="text-xl font-bold text-white font-mono mb-6">New VAPT Project</h2>
        <form id="createForm" class="space-y-4">
            <div>
                <label class="block text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">Project Name *</label>
                <input type="text" name="name" required class="w-full bg-dark-900 border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-500 font-mono text-sm">
            </div>
            <div>
                <label class="block text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">Scope</label>
                <input type="text" name="scope" placeholder="e.g., Internet Banking, Mobile App" class="w-full bg-dark-900 border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-500 font-mono text-sm">
            </div>
            <div class="grid grid-cols-2 gap-4">
                <div>
                    <label class="block text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">Start Date *</label>
                    <input type="date" name="start_date" required class="w-full bg-dark-900 border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-500 font-mono text-sm">
                </div>
                <div>
                    <label class="block text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">End Date *</label>
                    <input type="date" name="end_date" required class="w-full bg-dark-900 border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-500 font-mono text-sm">
                </div>
            </div>
            <div>
                <label class="block text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">Description</label>
                <textarea name="description" rows="3" class="w-full bg-dark-900 border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-500 font-mono text-sm resize-none"></textarea>
            </div>
            <div class="flex gap-3 pt-2">
                <button type="button" onclick="hideCreateModal()" class="flex-1 border border-gray-700 text-gray-400 py-3 rounded-lg hover:bg-dark-700 transition-all font-mono text-sm">CANCEL</button>
                <button type="submit" class="flex-1 bg-cyber-500 hover:bg-cyber-400 text-dark-900 font-bold py-3 rounded-lg transition-all font-mono text-sm">CREATE</button>
            </div>
        </form>
    </div>
</div>

<script>
async function loadProjects() {
    const projects = await api("/projects");
    const grid = document.getElementById("projects-grid");
    grid.innerHTML = "";
    
    if (projects.length === 0) {
        document.getElementById("empty-state").classList.remove("hidden");
        return;
    }
    
    projects.forEach((p, i) => {
        const findings = p.findings || [];
        const criticalCount = findings.filter(f => f.severity === 'critical').length;
        const highCount = findings.filter(f => f.severity === 'high').length;
        
        const card = document.createElement("div");
        card.className = "bg-dark-800 border border-gray-800 rounded-xl p-6 hover:border-cyber-500/30 transition-all";
        card.style.animationDelay = `${i * 0.05}s`;
        card.innerHTML = `
            <div class="flex items-start justify-between mb-4">
                <div class="flex-1">
                    <h3 class="font-mono font-bold text-white text-lg leading-tight">${p.name}</h3>
                    <p class="text-gray-500 text-xs mt-1 font-mono">${p.scope || 'No scope'}</p>
                </div>
                <span class="px-2.5 py-1 rounded-full text-xs font-mono font-semibold ${statusBadge(p.status)} ml-3 shrink-0">
                    ${p.status.replace('_',' ').toUpperCase()}
                </span>
            </div>
            
            <div class="space-y-2 mb-5">
                <div class="flex items-center gap-2 text-gray-400 text-sm font-mono">
                    <svg class="w-4 h-4 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
                    <span>${p.start_date} → ${p.end_date}</span>
                </div>
            </div>
            
            <div class="flex gap-2 mb-5 flex-wrap">
                ${criticalCount > 0 ? `<span class="px-2.5 py-1 rounded text-xs font-mono bg-red-900/50 text-red-400 border border-red-800">${criticalCount} Critical</span>` : ''}
                ${highCount > 0 ? `<span class="px-2.5 py-1 rounded text-xs font-mono bg-orange-900/50 text-orange-400 border border-orange-800">${highCount} High</span>` : ''}
                <span class="px-2.5 py-1 rounded text-xs font-mono bg-dark-700 text-gray-400 border border-gray-700">${findings.length} Total</span>
            </div>
            
            <a href="/projects/${p.id}" class="block w-full text-center border border-cyber-500/30 text-cyber-400 hover:bg-cyber-500/10 py-2.5 rounded-lg transition-all font-mono text-sm">
                View Details →
            </a>
        `;
        grid.appendChild(card);
    });
}

function showCreateModal() {
    document.getElementById("create-modal").classList.remove("hidden");
    document.getElementById("create-modal").classList.add("flex");
}
function hideCreateModal() {
    document.getElementById("create-modal").classList.add("hidden");
    document.getElementById("create-modal").classList.remove("flex");
}

document.getElementById("createForm").onsubmit = async (e) => {
    e.preventDefault();
    const data = new FormData(e.target);
    try {
        await api("/projects/", {
            method: "POST",
            body: JSON.stringify({
                name: data.get("name"),
                scope: data.get("scope"),
                start_date: data.get("start_date"),
                end_date: data.get("end_date"),
                description: data.get("description"),
                status: "planning"
            })
        });
        hideCreateModal();
        loadProjects();
    } catch(err) {
        alert("Failed to create project: " + err.message);
    }
};

loadProjects();
</script>
{% endblock %}
```

---

### Task 20: Project Detail Page (with Findings Display)

**Create:** `~/pentest-manager/templates/project_detail.html`

```html
{% extends "base.html" %}
{% block title %}Project Detail{% endblock %}
{% block content %}
<nav class="border-b border-gray-800 bg-dark-900/80 backdrop-blur-sm sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
        <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded bg-cyber-500/20 border border-cyber-500/30 flex items-center justify-center">
                <svg class="w-5 h-5 text-cyber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                </svg>
            </div>
            <span class="font-mono text-lg font-bold text-white">VAPT<span class="text-cyber-400">Manager</span></span>
            <span class="text-gray-600">/</span>
            <a href="/projects" class="font-mono text-gray-400 hover:text-white transition-colors">Projects</a>
            <span class="text-gray-600">/</span>
            <span id="breadcrumb-name" class="font-mono text-gray-400">Loading...</span>
        </div>
        <div class="flex items-center gap-4">
            <a href="/projects" class="text-gray-400 hover:text-white transition-colors text-sm font-mono">← Back</a>
        </div>
    </div>
</nav>

<main class="max-w-7xl mx-auto px-6 py-8">
    <!-- Project Header -->
    <div class="bg-dark-800 border border-gray-800 rounded-xl p-6 mb-6">
        <div class="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
            <div>
                <h1 id="project-name" class="text-2xl font-bold text-white font-mono tracking-tight">Loading...</h1>
                <p id="project-scope" class="text-gray-500 mt-1 font-mono text-sm"></p>
                <p id="project-desc" class="text-gray-600 mt-2 text-sm"></p>
            </div>
            <div class="flex gap-3 flex-wrap">
                <a id="report-btn" href="#" class="bg-red-600/20 border border-red-600/30 text-red-400 hover:bg-red-600/30 py-2.5 px-5 rounded-lg transition-all font-mono text-sm">
                    📄 Export PDF
                </a>
                <button onclick="showAddFindingModal()" class="bg-cyber-500/20 border border-cyber-500/30 text-cyber-400 hover:bg-cyber-500/30 py-2.5 px-5 rounded-lg transition-all font-mono text-sm">
                    + Add Finding
                </button>
            </div>
        </div>
        
        <!-- Project Meta -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 pt-6 border-t border-gray-800">
            <div>
                <div class="text-gray-500 text-xs font-mono uppercase tracking-wider">Status</div>
                <div id="project-status" class="mt-1"></div>
            </div>
            <div>
                <div class="text-gray-500 text-xs font-mono uppercase tracking-wider">Start Date</div>
                <div id="project-start" class="text-white font-mono mt-1"></div>
            </div>
            <div>
                <div class="text-gray-500 text-xs font-mono uppercase tracking-wider">End Date</div>
                <div id="project-end" class="text-white font-mono mt-1"></div>
            </div>
            <div>
                <div class="text-gray-500 text-xs font-mono uppercase tracking-wider">Total Findings</div>
                <div id="project-findings-count" class="text-white font-mono mt-1"></div>
            </div>
        </div>
    </div>
    
    <!-- Findings Section -->
    <div class="mb-6 flex items-center justify-between">
        <h2 class="text-xl font-bold text-white font-mono">Vulnerabilities</h2>
        <div class="flex gap-2">
            <button onclick="filterFindings('all')" class="filter-btn px-3 py-1.5 rounded text-xs font-mono bg-dark-700 text-gray-400 hover:text-white transition-all" data-filter="all">All</button>
            <button onclick="filterFindings('critical')" class="filter-btn px-3 py-1.5 rounded text-xs font-mono bg-dark-700 text-red-400 hover:text-red-300 transition-all" data-filter="critical">Critical</button>
            <button onclick="filterFindings('high')" class="filter-btn px-3 py-1.5 rounded text-xs font-mono bg-dark-700 text-orange-400 hover:text-orange-300 transition-all" data-filter="high">High</button>
            <button onclick="filterFindings('medium')" class="filter-btn px-3 py-1.5 rounded text-xs font-mono bg-dark-700 text-yellow-400 hover:text-yellow-300 transition-all" data-filter="medium">Medium</button>
        </div>
    </div>
    
    <div id="findings-list" class="space-y-4"></div>
    <div id="no-findings" class="hidden text-center py-12">
        <div class="text-gray-600 font-mono">No vulnerabilities recorded yet</div>
    </div>
</main>

<!-- Add Finding Modal -->
<div id="finding-modal" class="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 hidden items-center justify-center p-4 overflow-y-auto">
    <div class="bg-dark-800 border border-gray-700 rounded-2xl w-full max-w-2xl p-8 my-8">
        <h2 class="text-xl font-bold text-white font-mono mb-6">Add Vulnerability Finding</h2>
        <form id="findingForm" class="space-y-4">
            <div>
                <label class="block text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">Title *</label>
                <input type="text" name="title" required class="w-full bg-dark-900 border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-500 font-mono text-sm">
            </div>
            <div class="grid grid-cols-2 gap-4">
                <div>
                    <label class="block text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">Severity *</label>
                    <select name="severity" required class="w-full bg-dark-900 border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-500 font-mono text-sm">
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                        <option value="informational">Informational</option>
                    </select>
                </div>
                <div>
                    <label class="block text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">Status</label>
                    <select name="status" class="w-full bg-dark-900 border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-500 font-mono text-sm">
                        <option value="open">Open</option>
                        <option value="in_progress">In Progress</option>
                        <option value="resolved">Resolved</option>
                        <option value="accepted">Accepted</option>
                        <option value="false_positive">False Positive</option>
                    </select>
                </div>
            </div>
            <div class="grid grid-cols-2 gap-4">
                <div>
                    <label class="block text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">CVE ID</label>
                    <input type="text" name="cve_id" placeholder="e.g., CVE-2024-1234" class="w-full bg-dark-900 border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-500 font-mono text-sm">
                </div>
                <div>
                    <label class="block text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">CVSS Score</label>
                    <input type="number" name="cvss_score" step="0.1" min="0" max="10" placeholder="e.g., 9.8" class="w-full bg-dark-900 border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-500 font-mono text-sm">
                </div>
            </div>
            <div>
                <label class="block text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">Description</label>
                <textarea name="description" rows="3" class="w-full bg-dark-900 border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-500 font-mono text-sm resize-none"></textarea>
            </div>
            <div>
                <label class="block text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">Impact</label>
                <textarea name="impact" rows="2" class="w-full bg-dark-900 border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-500 font-mono text-sm resize-none"></textarea>
            </div>
            <div>
                <label class="block text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">Remediation</label>
                <textarea name="remediation" rows="2" class="w-full bg-dark-900 border border-gray-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-cyber-500 font-mono text-sm resize-none"></textarea>
            </div>
            <div class="flex gap-3 pt-2">
                <button type="button" onclick="hideFindingModal()" class="flex-1 border border-gray-700 text-gray-400 py-3 rounded-lg hover:bg-dark-700 transition-all font-mono text-sm">CANCEL</button>
                <button type="submit" class="flex-1 bg-cyber-500 hover:bg-cyber-400 text-dark-900 font-bold py-3 rounded-lg transition-all font-mono text-sm">ADD FINDING</button>
            </div>
        </form>
    </div>
</div>

<script>
const PROJECT_ID = {{ project_id }};
let allFindings = [];

async function loadProject() {
    const p = await api(`/projects/${PROJECT_ID}`);
    allFindings = p.findings || [];
    
    document.getElementById("project-name").textContent = p.name;
    document.getElementById("project-scope").textContent = p.scope || 'No scope defined';
    document.getElementById("project-desc").textContent = p.description || '';
    document.getElementById("project-start").textContent = p.start_date;
    document.getElementById("project-end").textContent = p.end_date;
    document.getElementById("project-findings-count").textContent = (p.findings || []).length + " vulnerabilities";
    document.getElementById("breadcrumb-name").textContent = p.name;
    
    const statusEl = document.getElementById("project-status");
    statusEl.innerHTML = `<span class="px-2.5 py-1 rounded-full text-xs font-mono font-semibold ${statusBadge(p.status)}">${p.status.replace('_',' ').toUpperCase()}</span>`;
    
    document.getElementById("report-btn").href = `/api/reports/project/${PROJECT_ID}/pdf`;
    
    renderFindings(allFindings);
}

function renderFindings(findings) {
    const list = document.getElementById("findings-list");
    list.innerHTML = "";
    
    if (findings.length === 0) {
        document.getElementById("no-findings").classList.remove("hidden");
        return;
    }
    document.getElementById("no-findings").classList.add("hidden");
    
    findings.forEach((f, i) => {
        const card = document.createElement("div");
        card.className = `finding-card bg-dark-800 border border-gray-800 rounded-xl p-6 hover:border-gray-700 transition-all animate-in`;
        card.dataset.severity = f.severity;
        card.style.animationDelay = `${i * 0.05}s`;
        
        card.innerHTML = `
            <div class="flex items-start gap-4">
                <div class="shrink-0 mt-1">
                    <span class="inline-block px-2.5 py-1 rounded text-xs font-mono font-bold ${sevClass(f.severity)}">${f.severity.toUpperCase()}</span>
                </div>
                <div class="flex-1 min-w-0">
                    <div class="flex items-start justify-between gap-4">
                        <h3 class="font-mono font-semibold text-white text-base leading-tight">${f.title}</h3>
                        <span class="shrink-0 px-2 py-0.5 rounded text-xs font-mono ${statusBadge(f.status)}">${f.status.replace('_',' ').toUpperCase()}</span>
                    </div>
                    
                    <div class="flex gap-4 mt-2 flex-wrap">
                        ${f.cve_id ? `<span class="text-xs font-mono text-gray-500">${f.cve_id}</span>` : ''}
                        ${f.cvss_score != null ? `<span class="text-xs font-mono text-gray-500">CVSS: <span class="text-${f.cvss_score >= 9 ? 'red' : f.cvss_score >= 7 ? 'orange' : 'yellow'}-400">${f.cvss_score}</span></span>` : ''}
                    </div>
                    
                    ${f.description ? `<p class="text-gray-400 text-sm mt-3 leading-relaxed">${f.description}</p>` : ''}
                    
                    ${f.impact ? `<div class="mt-3"><span class="text-xs font-mono text-red-400 uppercase tracking-wider">Impact: </span><span class="text-gray-400 text-sm">${f.impact}</span></div>` : ''}
                    
                    ${f.remediation ? `<div class="mt-2"><span class="text-xs font-mono text-cyber-400 uppercase tracking-wider">Remediation: </span><span class="text-gray-400 text-sm">${f.remediation}</span></div>` : ''}
                    
                    <div class="mt-4 flex gap-2">
                        <button onclick="deleteFinding(${f.id})" class="text-xs font-mono text-red-400 hover:text-red-300 transition-colors border border-red-900/50 hover:border-red-700 px-3 py-1.5 rounded">Delete</button>
                    </div>
                </div>
            </div>
        `;
        list.appendChild(card);
    });
}

let currentFilter = 'all';
function filterFindings(severity) {
    currentFilter = severity;
    document.querySelectorAll('.filter-btn').forEach(b => {
        b.classList.remove('ring-1', 'ring-cyber-500/50');
    });
    document.querySelector(`[data-filter="${severity}"]`).classList.add('ring-1', 'ring-cyber-500/50');
    
    const filtered = severity === 'all' ? allFindings : allFindings.filter(f => f.severity === severity);
    renderFindings(filtered);
}

async function deleteFinding(id) {
    if (!confirm("Delete this finding?")) return;
    await api(`/findings/${id}`, { method: "DELETE" });
    loadProject();
}

function showAddFindingModal() {
    document.getElementById("finding-modal").classList.remove("hidden");
    document.getElementById("finding-modal").classList.add("flex");
}
function hideFindingModal() {
    document.getElementById("finding-modal").classList.add("hidden");
    document.getElementById("finding-modal").classList.remove("flex");
    document.getElementById("findingForm").reset();
}

document.getElementById("findingForm").onsubmit = async (e) => {
    e.preventDefault();
    const data = new FormData(e.target);
    const payload = {
        project_id: PROJECT_ID,
        title: data.get("title"),
        severity: data.get("severity"),
        status: data.get("status"),
        cve_id: data.get("cve_id") || null,
        cvss_score: data.get("cvss_score") ? parseFloat(data.get("cvss_score")) : null,
        description: data.get("description") || null,
        impact: data.get("impact") || null,
        remediation: data.get("remediation") || null
    };
    await api("/findings/", { method: "POST", body: JSON.stringify(payload) });
    hideFindingModal();
    loadProject();
};

loadProject();
</script>
{% endblock %}
```

---

## Phase 8: Installation + Verification

### Task 21: Install Dependencies

```bash
cd ~/pentest-manager
pip install -r requirements.txt
```

### Task 22: Run Server

```bash
cd ~/pentest-manager
python run.py
```

Server akan jalan di: `http://192.168.10.239:8000`

### Task 23: Verification Steps

1. Buka `http://192.168.10.239:8000/login`
2. Login: `admin` / `admin123`
3. Buat project baru (pastikan start_date & end_date wajib)
4. Tambah finding dengan severity
5. Lihat finding muncul di project detail
6. Download PDF report

---

## Verification Checklist

- [ ] `/login` — Dark mode login dengan aesthetic cyber security ✅
- [ ] `/dashboard` — Stats cards + recent projects table ✅
- [ ] `/projects` — Project cards grid dengan findings summary ✅
- [ ] `/projects/{id}` — Detail project dengan full vulnerability list ✅
- [ ] Start date + End date required di project creation ✅
- [ ] PDF report export ✅
- [ ] Severity badges (Critical=red, High=orange, Medium=yellow, Low=blue, Info=gray) ✅
- [ ] Filter findings by severity ✅
- [ ] Mobile responsive dark UI ✅

---

## Aesthetic Summary (frontend-design principles applied)

- **Dark theme**: #020617 background, cyber green (#00ff88) accents
- **Typography**: JetBrains Mono (headers/code) + Inter (body) — distinctive, NOT Inter/Roboto generic
- **Motion**: Staggered fade-in animations on page load
- **Layout**: Clean card-based dashboard with subtle grid background texture
- **Feel**: Professional SOC/dashboard aesthetic with premium polish, NOT generic AI slop
- **Micro-interactions**: Hover glow effects, hover states on cards and buttons
- **Color coding**: Severity-driven color system (red=critical, orange=high, yellow=medium, blue=low, gray=info)
