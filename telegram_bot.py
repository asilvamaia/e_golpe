import os
import logging
import telebot
import asyncio
from pathlib import Path
from colorama import init

from database.db import SessionLocal
from database.models import Usuario

# Importa as funções core diretamente
from core import (
    extrair_url,
    desencurtar_link,
    limpar_dominio,
    validar_seguranca_url,
    checar_cache_analise,
    orquestrar_coleta_dados_url,
    analisar_com_ia,
    analisar_texto_ia,
    analisar_arquivo_ia
)

# --- 1. CONFIGURAÇÃO E CONSTANTES ---

init(autoreset=True)

pasta_atual = Path(__file__).parent
if os.path.exists("/data"):
    PASTA_DADOS = Path("/data")
else:
    PASTA_DADOS = pasta_atual

LOG_FILE = PASTA_DADOS / "sistema.log"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

def registrar_log(mensagem, nivel="INFO"):
    print(f"[{nivel}] {mensagem}")
    if nivel == "INFO": logging.info(mensagem)
    elif nivel == "ERRO": logging.error(mensagem)
    elif nivel == "ALERTA": logging.warning(mensagem)

# --- INICIALIZAÇÃO DO BOT ---
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

bot = None
if TELEGRAM_TOKEN:
    bot = telebot.TeleBot(TELEGRAM_TOKEN)

# --- 2. AUXILIARES ---

def registrar_usuario(user_id):
    db = SessionLocal()
    try:
        if not db.query(Usuario).filter(Usuario.user_id == str(user_id)).first():
            db.add(Usuario(user_id=str(user_id)))
            db.commit()
            bot.send_message(
                user_id, 
                "🔔 *Bem-vindo ao GuardianBot!*\n\nVocê agora está protegido. Envie qualquer link suspeito ou mensagem duvidosa e eu analisarei para você!", 
                parse_mode='Markdown'
            )
            registrar_log(f"Novo usuário registrado no Telegram: {user_id}", "INFO")
    finally:
        db.close()

# --- 3. BOT HANDLERS ---

if bot:
    @bot.message_handler(commands=['start', 'help'])
    def send_welcome(message):
        registrar_usuario(message.from_user.id)
        bot.reply_to(message, "Olá! 🛡️\nSou o GuardianBot.\nEnvie um LINK ou MENSAGEM para verificar.")

    @bot.message_handler(commands=['doar', 'apoiar'])
    def pedir_doacao(message):
        bot.reply_to(message, "☕ **Apoie o GuardianBot!**\n\nAjude a manter o projeto vivo: https://livepix.gg/asmaia", parse_mode="Markdown")

    @bot.message_handler(func=lambda message: True)
    def processar_mensagem(message):
        registrar_usuario(message.from_user.id)
        texto_usuario = message.text
        url = extrair_url(texto_usuario)
        meta_telegram = {"origem": "Telegram", "user_id": message.from_user.id, "nome": message.from_user.first_name}

        if url:
            msg_wait = bot.reply_to(message, "🔎 Verificando link...")
            url_final, foi_desencurtado = desencurtar_link(url)
            if foi_desencurtado:
                 bot.edit_message_text(chat_id=message.chat.id, message_id=msg_wait.message_id, text=f"🔎 Link redirecionado. Analisando: **{limpar_dominio(url_final)}**...", parse_mode="Markdown")
            
            # Validação DNS / Host
            seguro_tecnico, motivo, url_validada = validar_seguranca_url(url_final)
            if not seguro_tecnico:
                bot.edit_message_text(chat_id=message.chat.id, message_id=msg_wait.message_id, text=f"🚫 **Bloqueado:** {motivo}")
                return
            
            url_final = url_validada

            try:
                cache_analise, _ = checar_cache_analise(url_final)
                if cache_analise:
                    analise = cache_analise + "\n\n*(⚡ Resultado em cache)*"
                else:
                    dados = asyncio.run(orquestrar_coleta_dados_url(url_final))
                    analise = asyncio.run(analisar_com_ia(url_final, dados, origem="telegram", metadados=meta_telegram))
                    
                bot.edit_message_text(chat_id=message.chat.id, message_id=msg_wait.message_id, text=analise, parse_mode="Markdown")
            except Exception as e:
                bot.edit_message_text(chat_id=message.chat.id, message_id=msg_wait.message_id, text=f"Erro: {e}")
        else:
            msg_wait = bot.reply_to(message, "🔎 Lendo mensagem...")
            
            try:
                cache_analise, _ = checar_cache_analise(texto_usuario)
                if cache_analise:
                     analise = cache_analise + "\n\n*(⚡ Resultado em cache)*"
                else:
                     # CORREÇÃO: analisar_texto_ia é síncrona, removemos asyncio.run
                     analise = analisar_texto_ia(texto_usuario, origem="telegram", metadados=meta_telegram)
                bot.edit_message_text(chat_id=message.chat.id, message_id=msg_wait.message_id, text=analise, parse_mode="Markdown")
            except Exception as e:
                bot.edit_message_text(chat_id=message.chat.id, message_id=msg_wait.message_id, text=f"Erro: {e}")

    @bot.message_handler(content_types=['photo', 'document'])
    def processar_arquivo(message):
        registrar_usuario(message.from_user.id)
        
        is_document = message.content_type == 'document'
        
        if is_document:
            if not message.document.mime_type.startswith('image/') and message.document.mime_type != 'application/pdf':
                bot.reply_to(message, "Por enquanto só analiso Imagens ou arquivos PDF.")
                return
            msg_wait = bot.reply_to(message, "📄 Baixando e analisando arquivo...")
            file_info_id = message.document.file_id
            mime_type = message.document.mime_type
            origem_meta = "Telegram (Documento)"
        else:
            msg_wait = bot.reply_to(message, "👁️ Baixando e analisando imagem (OCR)...")
            file_info_id = message.photo[-1].file_id
            mime_type = "image/jpeg"
            origem_meta = "Telegram (Imagem)"
            
        meta_telegram = {"origem": origem_meta, "user_id": message.from_user.id, "nome": message.from_user.first_name}
        
        try:
            file_info = bot.get_file(file_info_id)
            downloaded_file = bot.download_file(file_info.file_path)
            
            analise = asyncio.run(analisar_arquivo_ia(downloaded_file, mime_type, origem="telegram", metadados=meta_telegram))
            bot.edit_message_text(chat_id=message.chat.id, message_id=msg_wait.message_id, text=analise, parse_mode="Markdown")
            
        except Exception as e:
            registrar_log(f"Erro no Telegram ao analisar arquivo/foto: {e}", "ERRO")
            bot.edit_message_text(chat_id=message.chat.id, message_id=msg_wait.message_id, text="Desculpe, não consegui analisar o arquivo. Tente enviar de novo.")

if __name__ == '__main__' and TELEGRAM_TOKEN:
    print("Bot Telegram Iniciado")
    bot.infinity_polling()
