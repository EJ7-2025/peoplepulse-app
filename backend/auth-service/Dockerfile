# Dockerfile para o auth-service do PeoplePulse

# 1. Use uma imagem base oficial do Python.
FROM python:3.9-slim

# 2. Defina o diretório de trabalho dentro do contêiner.
WORKDIR /app

# 3. Copie o arquivo de dependências e instale-as.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copie o resto do código da aplicação.
COPY . .

# 5. Exponha a porta que a aplicação irá rodar. O Cloud Run usa a 8080 por padrão.
EXPOSE 8080

# 6. O comando para iniciar a aplicação quando o contêiner rodar.
CMD uvicorn main:app --host 0.0.0.0 --port $PORT
