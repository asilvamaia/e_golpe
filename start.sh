#!/bin/bash

# Script de inicialização do IA Contra Fraude (Backend + API + Telegram)

cd /app || exit 1

# 1. Inicia o Bot do Telegram em segundo plano se o token estiver configurado
if [ -n "$TELEGRAM_BOT_TOKEN" ]; then
    echo "🤖 Iniciando Bot do Telegram em segundo plano..."
    python telegram_bot.py &
else
    echo "ℹ️ TELEGRAM_BOT_TOKEN não configurado. Bot do Telegram não iniciado."
fi

# 2. Inicia a API FastAPI na porta local 8000
echo "⚡ Iniciando API FastAPI (Porta 8000)..."
uvicorn main:app --host 127.0.0.1 --port 8000 &

# 3. Inicia o Nginx no primeiro plano (foreground) para escutar nas portas 80 e 8080
echo "🛡️ Iniciando Nginx (Proxy Reverso)..."
nginx -c /app/nginx.conf -g "daemon off;"