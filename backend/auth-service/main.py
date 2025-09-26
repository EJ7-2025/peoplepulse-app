# main.py - v2, CORRIGIDO E SIMPLIFICADO

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
import time
import jwt
from passlib.context import CryptContext

# --- Configuração ---
SECRET_KEY = "uma-chave-secreta-muito-forte-para-desenvolvimento"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI(title="PeoplePulse Auth Service")

# --- Modelos de Dados (Pydantic) ---
class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    role: str

# Simulação de um banco de dados de usuários
fake_users_db = {
    "colaborador@peoplepulse.com": { "username": "Ana Silva", "hashed_password": "$2b$12$EixZaYVK1fsAH2S52e3yX.L3mo23dIrg39B4i2I63wz3W2p.w.4sS", "role": "colaborador" },
    "gestor@peoplepulse.com": { "username": "Ricardo Borges", "hashed_password": "$2b$12$EixZaYVK1fsAH2S52e3yX.L3mo23dIrg39B4i2I63wz3W2p.w.4sS", "role": "gestor" },
    "rh@peoplepulse.com": { "username": "Sandra Marques", "hashed_password": "$2b$12$EixZaYVK1fsAH2S52e3yX.L3mo23dIrg39B4i2I63wz3W2p.w.4sS", "role": "rh" },
    "diretoria@peoplepulse.com": { "username": "Marcos Andrade", "hashed_password": "$2b$12$EixZaYVK1fsAH2S52e3yX.L3mo23dIrg39B4i2I63wz3W2p.w.4sS", "role": "diretoria" }
}

# --- Funções de Utilitário ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user_from_db(username: str):
    if username in fake_users_db:
        user_data = fake_users_db[username]
        return User(username=user_data["username"], role=user_data["role"])
    return None

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = int(time.time()) + (ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Endpoints da API ---
@app.post("/auth/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user_in_db = fake_users_db.get(form_data.username)
    if not user_in_db or not verify_password(form_data.password, user_in_db["hashed_password"]):
        raise HTTPException(status_code=401, detail="Email ou senha incorretos", headers={"WWW-Authenticate": "Bearer"})
    
    user = get_user_from_db(form_data.username)
    access_token = create_access_token(data={"sub": form_data.username, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/")
def read_root():
    return {"status": "Auth Service is running"}
