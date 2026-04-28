from sqlalchemy import Column, Integer, String, Text, Date, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
import enum

class ProjectStatus(str, enum.Enum):
    PROPOSAL = "PROPOSAL"
    SCOPING = "SCOPING"
    ONGOING = "ONGOING"
    REMEDIATION = "REMEDIATION"
    FINISHED = "FINISHED"

class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    vendor_name = Column(String(200), nullable=True)  # Nama vendor
    description = Column(Text, nullable=True)
    status = Column(Enum(ProjectStatus), default=ProjectStatus.PROPOSAL)
    start_date = Column(Date, nullable=False)
    end_date = Column(Date, nullable=False)
    scope = Column(Text, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    targets = relationship("Target", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")
    creator = relationship("User", foreign_keys=[created_by])
