from datetime import datetime,timedelta,timezone
import jwt
from passlib.context import CryptContext
from .config import settings
pwd=CryptContext(schemes=["bcrypt"],deprecated="auto")
def hash_password(p): return pwd.hash(p)
def verify_password(p,h): return pwd.verify(p,h)
def create_token(username,role):
    return jwt.encode({"sub":username,"role":role,"exp":datetime.now(timezone.utc)+timedelta(hours=12)},settings.secret_key,algorithm="HS256")
