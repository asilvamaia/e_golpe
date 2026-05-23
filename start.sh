#!/bin/bash

# Script de inicialização unificado do GuardianBot
# Este script inicia todos os três serviços simultaneamente sob o mesmo container.

# 1. Inicia o Bot do Telegram em segundo plano
echo "🤖 Iniciando Bot do Telegram em segundo plano..."
python telegram_bot.py &

# 2. Inicia a API FastAPI (Extensão/Backend) em segundo plano na porta local 8000
echo "⚡ Iniciando API FastAPI (Porta 8000) em segundo plano..."
uvicorn main:app --host 127.0.0.1 --port 8000 &

# 3. Inicia o Site Streamlit em segundo plano na porta local 8501
echo "🖥️ Iniciando Site Streamlit (Porta 8501) em segundo plano..."
streamlit run app.py --server.port 8501 --server.address 127.0.0.1 --server.headless true &

# 4. Inicia o Nginx no primeiro plano (foreground) para escutar na porta pública 8080
# Ele fará o proxy reverso: requisições de /api/* e /check-* para o FastAPI, e o restante para o Streamlit.
echo "🛡️ Iniciando Nginx na porta 8080 (Proxy Reverso)..."
nginx -g "daemon off;"