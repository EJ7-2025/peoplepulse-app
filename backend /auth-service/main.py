# Versão 1.0.0 - Disparando o primeiro deploy
# main.py - Serviço de Autenticação do PeoplePulse
# NOTA: Esta é a primeira versão do nosso serviço.
# Ele define a estrutura da API, os modelos de dados e uma lógica de login simulada.
# Nos próximos passos, conectaremos a um banco de dados real.

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional
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
    email: Optional[str] = None
    role: str
    disabled: bool = False

# Simulação de um banco de dados de usuários
fake_users_db = {
    "colaborador@peoplepulse.com": {
        "username": "Ana Silva", "email": "colaborador@peoplepulse.com",
        "hashed_password": "$2b$12$EixZaYVK1fsAH2S52e3yX.L3mo23dIrg39B4i2I63wz3W2p.w.4sS", # Senha: 123
        "role": "colaborador", "disabled": False,
    },
    "gestor@peoplepulse.com": {
        "username": "Ricardo Borges", "email": "gestor@peoplepulse.com",
        "hashed_password": "$2b$12$EixZaYVK1fsAH2S52e3yX.L3mo23dIrg39B4i2I63wz3W2p.w.4sS", # Senha: 123
        "role": "gestor", "disabled": False,
    },
    "rh@peoplepulse.com": {
        "username": "Sandra Marques", "email": "rh@peoplepulse.com",
        "hashed_password": "$2b$12$EixZaYVK1fsAH2S52e3yX.L3mo23dIrg39B4i2I63wz3W2p.w.4sS", # Senha: 123
        "role": "rh", "disabled": False,
    },
    "diretoria@peoplepulse.com": {
        "username": "Marcos Andrade", "email": "diretoria@peoplepulse.com",
        "hashed_password": "$2b$12$EixZaYVK1fsAH2S52e3yX.L3mo23dIrg39B4i2I63wz3W2p.w.4sS", # Senha: 123
        "role": "diretoria", "disabled": False,
    }
}

# --- Funções de Utilitário ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return User(**user_dict)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = int(time.time()) + (ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- Endpoints da API ---
@app.post("/auth/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(fake_users_db, form_data.username)
    if not user or not verify_password(form_data.password, fake_users_db[user.email]["hashed_password"]):
        raise HTTPException(status_code=401, detail="Email ou senha incorretos", headers={"WWW-Authenticate": "Bearer"},)

    access_token = create_access_token(data={"sub": user.email, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/")
def read_root():
    return {"status": "Auth Service is running"}
