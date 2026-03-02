# Usa uma imagem leve do Python
FROM python:3.10-slim

# Instala o comando 'whois' do sistema (necessário para a lib python-whois funcionar)
RUN apt-get update && apt-get install -y whois && rm -rf /var/lib/apt/lists/*

# Cria a pasta do app
WORKDIR /app

# Copia os arquivos da sua pasta para o servidor
COPY . .

# Instala as bibliotecas do Python
RUN pip install --no-cache-dir -r requirements.txt

# Comando para iniciar o bot
CMD ["python", "telegram_bot.py"]