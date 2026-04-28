from pydantic import BaseModel
from datetime import date, datetime
from typing import Optional, List

class FindingResponse(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    cve_id: Optional[str]
    cvss_score: Optional[float]
    owasp_category: Optional[str] = None
    description: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    class Config:
        from_attributes = True

class TargetResponse(BaseModel):
    id: int
    name: str
    target_type: str
    url: Optional[str]
    ip_address: Optional[str]
    owner: Optional[str]
    class Config:
        from_attributes = True

class ProjectBase(BaseModel):
    name: str
    vendor_name: Optional[str] = None
    description: Optional[str] = None
    scope: Optional[str] = None
    start_date: date
    end_date: date
    status: str = "PROPOSAL"

class ProjectCreate(ProjectBase):
    pass

class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    vendor_name: Optional[str] = None
    description: Optional[str] = None
    scope: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    status: Optional[str] = None

class ProjectResponse(ProjectBase):
    id: int
    created_at: Optional[datetime]
    findings: List[FindingResponse] = []
    targets: List[TargetResponse] = []
    class Config:
        from_attributes = True
