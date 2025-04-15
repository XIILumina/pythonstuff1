from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "User"

class UserLogin(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    role: str
    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str