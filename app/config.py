import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
WHITELISTED_IPS = ["127.0.0.1"]
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15