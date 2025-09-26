# main.py - v3 (Versão de Teste "À Prova de Falhas")

from fastapi import FastAPI
import os

app = FastAPI(title="PeoplePulse Auth Service - Test")

@app.get("/")
def read_root():
    """Endpoint raiz para verificar se o serviço está no ar."""
    return {"status": "Auth Service (v3) is running successfully!"}

@app.get("/health")
def health_check():
    """Endpoint de verificação de saúde."""
    return {"status": "ok"}
