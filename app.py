from fastapi import FastAPI,HTTPException
from fastapi.middleware.cors import CORSMiddleware
from os import getenv
from dotenv import load_dotenv
from datetime import datetime, timedelta
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from jose import jwt 

load_dotenv()

app = FastAPI()

origins =  [
   
    "http://127.0.0.1:5500",    
    "*",                        
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

SECRET_CEY =getenv("SECRET_CEY", "juda_maxfiy_kalit")
ALGORITM = getenv("ALGORITM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
class UserLogin(BaseModel):
    email: EmailStr
    password: str

user_db = {}

def get_hashhed_pass(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utenov() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encode_jwt = jwt.encode(to_encode, SECRET_CEY, algorithm=ALGORITM)
    return encode_jwt