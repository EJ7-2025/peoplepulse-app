# main.py - v1.0.0 (Produção MVP)
# Serviço de Autenticação com lógica de login e token JWT

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional
import jwt
from passlib.context import CryptContext
import time

# --- Configuração de Segurança ---
SECRET_KEY = "uma-chave-secreta-muito-forte-que-deve-vir-de-variaveis-de-ambiente"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# --- Aplicação FastAPI ---
app = FastAPI(title="PeoplePulse Auth Service")

# --- Modelos de Dados (Pydantic) ---
class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    email: str
    role: str

# --- Banco de Dados Simulado ---
# A senha '123' foi "hasheada" para o valor abaixo
hashed_password_mock = "$2b$12$EixZaYVK1fsAH2S52e3yX.L3mo23dIrg39B4i2I63wz3W2p.w.4sS"
fake_users_db = {
    "colaborador@peoplepulse.com": {"username": "Ana Silva", "email": "colaborador@peoplepulse.com", "hashed_password": hashed_password_mock, "role": "colaborador"},
    "gestor@peoplepulse.com": {"username": "Ricardo Borges", "email": "gestor@peoplepulse.com", "hashed_password": hashed_password_mock, "role": "gestor"}
}

# --- Funções de Utilitário ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = int(time.time()) + (ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = fake_users_db.get(email)
    if user is None:
        raise credentials_exception
    return User(**user)

# --- Endpoints da API ---
@app.post("/auth/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user_in_db = fake_users_db.get(form_data.username)
    if not user_in_db or not verify_password(form_data.password, user_in_db["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email ou senha incorretos")
    
    access_token = create_access_token(data={"sub": user_in_db["email"], "role": user_in_db["role"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    """Endpoint protegido que retorna os dados do usuário logado."""
    return current_user

@app.get("/")
def read_root():
    return {"status": "Auth Service (v1.0.0) is running"}
