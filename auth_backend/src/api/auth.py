import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

# Environment variable for JWT secret key & configurations
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-default")  # <-- Change for production!
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# ----- Password hashing context -----
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# ----- Token helpers -----
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    return payload

# ----- In-memory users "database" (replace with DB in production) -----
fake_users_db = {}

# ----- Pydantic Models -----
class UserInDB(BaseModel):
    email: EmailStr
    hashed_password: str
    full_name: Optional[str] = None

class User(BaseModel):
    email: EmailStr = Field(..., description="The user's email address")
    full_name: Optional[str] = Field(None, description="The user's full name")

class UserCreate(BaseModel):
    email: EmailStr = Field(..., description="The user's email address")
    password: str = Field(..., min_length=6, description="A strong password")
    full_name: Optional[str] = Field(None, description="The user's full name")

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# ----- FastAPI Router -----
router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)

# PUBLIC_INTERFACE
@router.post('/register', response_model=User, summary="Register a new user")
async def register(user: UserCreate):
    """Register a new user with email, password, and optional full name."""
    email = user.email.lower()
    if email in fake_users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_pw = get_password_hash(user.password)
    fake_users_db[email] = UserInDB(email=email, hashed_password=hashed_pw, full_name=user.full_name)
    return User(email=email, full_name=user.full_name)

# PUBLIC_INTERFACE
@router.post('/login', response_model=Token, summary="User login (obtain JWT token)")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate user, returning JWT if successful."""
    email = form_data.username.lower()
    user = fake_users_db.get(email)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# PUBLIC_INTERFACE
@router.get('/profile', response_model=User, summary="Get current user profile")
async def get_profile(current_user: UserInDB = Depends(lambda: get_current_user_dep())):
    """Get the profile of the currently authenticated user."""
    return User(email=current_user.email, full_name=current_user.full_name)

# --- Dependency for extracting current user ---
def get_current_user_dep(token: str = Depends(oauth2_scheme)):
    """Extract user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = fake_users_db.get(email.lower())
    if not user:
        raise credentials_exception
    return user

# PUBLIC_INTERFACE
@router.get('/validate', summary="Validate JWT token")
async def validate_token(current_user: UserInDB = Depends(lambda: get_current_user_dep())):
    """Validate token and confirm user authentication."""
    return {"email": current_user.email, "full_name": current_user.full_name, "authenticated": True}
