# Usa uma imagem leve do Python
FROM python:3.10-slim

# Instala o comando 'whois' do sistema e o Nginx
RUN apt-get update && apt-get install -y whois nginx && rm -rf /var/lib/apt/lists/*

# Copia a configuração do Nginx para unificar a API e o Streamlit
COPY nginx.conf /etc/nginx/sites-available/default

# Cria a pasta do app
WORKDIR /app

# Copia os arquivos da sua pasta para o servidor
COPY . .

# Instala as bibliotecas do Python
RUN pip install --no-cache-dir -r requirements.txt

# Comando para iniciar o bot
CMD ["python", "telegram_bot.py"]