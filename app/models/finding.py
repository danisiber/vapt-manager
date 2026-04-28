from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Enum, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import enum

class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"

class FindingStatus(str, enum.Enum):
    open = "open"
    in_progress = "in_progress"
    resolved = "resolved"
    accepted = "accepted"
    false_positive = "false_positive"

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    title = Column(String(300), nullable=False)
    severity = Column(Enum(Severity), default=Severity.medium)
    status = Column(Enum(FindingStatus), default=FindingStatus.open)
    cve_id = Column(String(50), nullable=True)
    cvss_score = Column(Float, nullable=True)
    owasp_category = Column(String(10), nullable=True)  # e.g., "A01", "A03"
    description = Column(Text, nullable=True)
    steps_to_reproduce = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    project = relationship("Project", back_populates="findings")
    target = relationship("Target", back_populates="findings")
