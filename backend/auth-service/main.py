# Versão de Teste "À Prova de Falhas"
from fastapi import FastAPI
import os

app = FastAPI(title="PeoplePulse Auth Service - Test")

@app.get("/")
def read_root():
    return {"status": "Auth Service (v3) is running successfully!"}

@app.get("/health")
def health_check():
    return {"status": "ok"}