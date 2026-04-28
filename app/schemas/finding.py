from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class FindingBase(BaseModel):
    title: str
    severity: str = "medium"
    status: str = "open"
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    owasp_category: Optional[str] = None  # e.g., "A01", "A03"
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
    owasp_category: Optional[str] = None
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
