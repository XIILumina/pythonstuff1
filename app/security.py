from fastapi import HTTPException, Request
from sqlalchemy.orm import Session
from . import models, config
from datetime import datetime, timedelta

def check_ip_whitelist(request: Request):
    client_ip = request.client.host
    if client_ip not in config.WHITELISTED_IPS:
        raise HTTPException(status_code=403, detail="IP address not allowed")

def check_brute_force(db: Session, user: models.User):
    if user.is_locked:
        if user.last_failed_attempt and datetime.utcnow() < user.last_failed_attempt + timedelta(minutes=config.LOCKOUT_MINUTES):
            raise HTTPException(status_code=403, detail="Account locked")
        else:
            user.is_locked = False
            user.failed_attempts = 0
            db.commit()

def record_failed_attempt(db: Session, user: models.User):
    user.failed_attempts += 1
    user.last_failed_attempt = datetime.utcnow()
    if user.failed_attempts >= config.MAX_LOGIN_ATTEMPTS:
        user.is_locked = True
    db.commit()