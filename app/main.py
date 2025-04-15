from fastapi import FastAPI, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from . import models, crud, auth, security, database, schemas
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import logging

app = FastAPI()
models.Base.metadata.create_all(bind=database.engine)

templates = Jinja2Templates(directory="templates")
logging.basicConfig(filename="security.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def get_current_user(token: str, db: Session = Depends(database.get_db)):
    payload = auth.verify_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = crud.get_user_by_username(db, payload["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/register/", response_model=schemas.UserOut)
def register_user(user: schemas.UserCreate, db: Session = Depends(database.get_db), request: Request = None):
    security.check_ip_whitelist(request)
    existing_user = crud.get_user_by_username(db, user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    db_user = crud.create_user(db, user.username, user.password, user.role)
    logging.info(f"User registered: {user.username} from {request.client.host}")
    return db_user

@app.post("/login/", response_model=schemas.Token)
def login(user: schemas.UserLogin, db: Session = Depends(database.get_db), request: Request = None):
    security.check_ip_whitelist(request)
    db_user = crud.get_user_by_username(db, user.username)
    
    if not db_user:
        crud.log_access_attempt(db, user.username, request.client.host, False)
        raise HTTPException(status_code=400, detail="Incorrect username")

    security.check_brute_force(db, db_user)
    if not auth.verify_password(user.password, db_user.hashed_password):
        crud.log_access_attempt(db, user.username, request.client.host, False)
        security.record_failed_attempt(db, db_user)
        raise HTTPException(status_code=400, detail="Incorrect password")
    
    db_user.failed_attempts = 0
    db.commit()
    token = auth.create_access_token(data={"sub": db_user.username})
    crud.log_access_attempt(db, user.username, request.client.host, True)
    logging.info(f"Successful login: {user.username} from {request.client.host}")
    return {"access_token": token, "token_type": "bearer"}

@app.get("/admin/", response_model=schemas.UserOut)
def admin_only(current_user: models.User = Depends(get_current_user)):
    if current_user.role != "Admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user