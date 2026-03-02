from sqlalchemy import Column, Integer, String, Boolean, Float, ForeignKey, DateTime
from sqlalchemy.orm import relationship
import datetime
from database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    
    # Relationships
    uploads = relationship("UploadHistory", back_populates="owner")
    logs = relationship("Log", back_populates="owner")

class UploadHistory(Base):
    __tablename__ = "upload_history"
    
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String)
    upload_date = Column(DateTime, default=datetime.datetime.utcnow)
    total_events = Column(Integer, default=0)
    anomalies_found = Column(Integer, default=0)
    
    # Foreign Key linking to the User
    user_id = Column(Integer, ForeignKey("users.id"))
    
    # Relationships
    owner = relationship("User", back_populates="uploads")
    logs = relationship("Log", back_populates="upload")

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    log_time = Column(String)
    user_login = Column(String)
    source_ip = Column(String)
    url = Column(String)
    action = Column(String)
    bytes_sent = Column(Float, default=0.0)
    bytes_received = Column(Float, default=0.0)
    
    # ML & AI Columns
    threat_name = Column(String, default="None")
    is_anomaly = Column(Boolean, default=False)
    ai_explanation = Column(String, nullable=True)
    confidence_score = Column(Float, nullable=True)
    
    # Foreign Keys linking the log to the user and the specific upload batch
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    upload_id = Column(Integer, ForeignKey("upload_history.id"), nullable=True)

    # Relationships
    owner = relationship("User", back_populates="logs")
    upload = relationship("UploadHistory", back_populates="logs")