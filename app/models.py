from sqlalchemy import Column, Integer, String, Boolean, DateTime
from .database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    hashed_password = Column(String)
    role = Column(String, default="User")
    is_locked = Column(Boolean, default=False)
    failed_attempts = Column(Integer, default=0)
    last_failed_attempt = Column(DateTime)

class AccessLog(Base):
    __tablename__ = "access_logs"
    id = Column(Integer, primary_key=True)
    username = Column(String)
    ip_address = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean)