from sqlalchemy.orm import Session
from . import models, auth

def create_user(db: Session, username: str, password: str, role: str) -> models.User:
    hashed_password = auth.hash_password(password)
    db_user = models.User(username=username, hashed_password=hashed_password, role=role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_user_by_username(db: Session, username: str) -> models.User:
    return db.query(models.User).filter(models.User.username == username).first()

def log_access_attempt(db: Session, username: str, ip_address: str, success: bool):
    log = models.AccessLog(username=username, ip_address=ip_address, success=success)
    db.add(log)
    db.commit()