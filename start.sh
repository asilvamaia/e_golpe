#!/bin/bash

# Este script decide qual serviço iniciar baseado na variável SERVICO configurada no Railway

if [ "$SERVICO" = "SITE" ]; then
    echo "Iniciando Streamlit..."
    # O Streamlit usará a porta que o Railway injetar na variável PORT (ou 8080 se ausente)
    export PORT="${PORT:-8080}"
    streamlit run app.py --server.port $PORT --server.address 0.0.0.0
else
    # O Padrão (ou se SERVICO=API) será iniciar a API FastAPI (Extensão)
    echo "Iniciando API FastAPI..."
    python main.py
fi