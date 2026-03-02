#!/bin/bash

# Inicia o Bot do Telegram em segundo plano (& no final faz isso)
#python telegram_bot.py &

# Inicia o Streamlit (Site) e diz para ele escutar na porta 8080 (padrão do Fly)
streamlit run app.py --server.port 8080 --server.address 0.0.0.0