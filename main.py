from fastapi import FastAPI, HTTPException, Security, Depends, File, UploadFile, Query
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import whois
from email_validator import validate_email, EmailNotValidError
import os
import secrets
import asyncio
import time
from typing import Optional, List, Dict, Any
from dotenv import load_dotenv

from core import (
    checar_cache_analise, 
    orquestrar_coleta_dados_url, 
    analisar_com_ia, 
    analisar_texto_ia,
    analisar_arquivo_ia,
    checar_senha_vazada,
    extrair_url,
    desencurtar_link,
    validar_seguranca_url,
    extrair_veredito_e_score,
    salvar_feedback,
    registrar_log
)
from database.db import SessionLocal
from database.models import DatasetItem, Feedback, Usuario

# Carrega variáveis de ambiente
load_dotenv()

API_KEY_NAME = "x-api-key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def get_api_key(api_key_header: Optional[str] = Security(api_key_header)):
    expected_api_key = os.environ.get("API_KEY_SECRET")
    expected_api_key = expected_api_key.strip() if expected_api_key else None
    
    # A ativação é explícita para não interromper clientes antigos durante a migração.
    # Em produção, configure REQUIRE_API_KEY=true e API_KEY_SECRET.
    if not expected_api_key:
        if os.environ.get("REQUIRE_API_KEY", "false").lower() == "true":
            raise HTTPException(status_code=503, detail="API não configurada com segurança.")
        return True
    
    if api_key_header and secrets.compare_digest(api_key_header.strip(), expected_api_key):
        return api_key_header
        
    raise HTTPException(
        status_code=403, 
        detail="Acesso Negado: Chave de API (x-api-key) ausente ou inválida."
    )

app = FastAPI(
    title="É Golpe? - IA Contra Fraude API", 
    description="API para detecção de fraudes, verificação de segurança, OCR de prints e checagem de vazamentos.",
    version="2.0.0"
)

cors_origins = [
    origin.strip()
    for origin in os.environ.get(
        "CORS_ALLOWED_ORIGINS",
        "https://fraude.servicos.ia.br,https://servicos.ia.br,https://servicos-ia.asilvamaia.chatgpt.site",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Modelos de Dados ---
class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=8000, description="Link ou texto de mensagem a ser analisado")
    source: Optional[str] = Field("mobile_app", description="Origem da requisição (mobile_app, extension, api)")

class AnalyzeTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=8000, description="Texto da mensagem suspeita (SMS, WhatsApp, e-mail)")
    source: Optional[str] = Field("mobile_app", description="Origem da requisição")

class EmailRequest(BaseModel):
    email: str

class DomainRequest(BaseModel):
    domain: str

class PasswordCheckRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=1024, description="Senha a ser verificada no Have I Been Pwned")

class FeedbackRequest(BaseModel):
    input_usuario: str
    output_ia: str
    avaliacao: str = Field(..., description="Gostei, NaoGostei, ou detalhe")

# --- Rotas Base ---

@app.get("/")
def home():
    return {
        "app": "É Golpe? (IA Contra Fraude)",
        "status": "online",
        "version": "2.0.0",
        "docs": "/docs"
    }

@app.get("/health")
@app.get("/api/v1/health")
def health_check():
    return {"status": "ok", "timestamp": str(time.time())}

# --- Rota Principal de Análise Unificada (Link ou Texto) ---

@app.post("/api/v1/analyze")
async def analyze_content(data: AnalyzeRequest, api_key: Any = Depends(get_api_key)):
    """
    Analisa um link ou mensagem de texto usando IA, bases globais de phishing e regras de segurança.
    """
    texto = data.text.strip()
    if not texto:
        raise HTTPException(status_code=400, detail="Texto ou URL não informado.")

    url = extrair_url(texto)
    meta = {"origem": data.source or "API"}
    
    if url:
        # 1. Trata URL
        url_final, foi_redirecionado = desencurtar_link(url)
        seguro_tecnico, motivo, url_validada = validar_seguranca_url(url_final)
        
        if not seguro_tecnico:
            fallback_block = f"**Veredito:** :red[**PERIGO (BLOQUEADO)**]\n\n🛡️ **Nível de Segurança:** 0/100\n\n**Análise:** O endereço fornecido foi bloqueado por segurança técnica ({motivo}).\n\n**Ação:** NÃO ACESSE este endereço."
            info = extrair_veredito_e_score(fallback_block)
            return {
                "status": "success",
                "cached": False,
                "type": "url",
                "url": url,
                "resolved_url": url_final,
                "verdict": info["veredito"],
                "score": info["score"],
                "level": info["nivel"],
                "icon": info["icone"],
                "analysis": fallback_block
            }
            
        url_final = url_validada
        
        try:
            cache_analise, _ = checar_cache_analise(url_final)
            if cache_analise:
                info = extrair_veredito_e_score(cache_analise)
                return {
                    "status": "success",
                    "cached": True,
                    "type": "url",
                    "url": url,
                    "resolved_url": url_final,
                    "verdict": info["veredito"],
                    "score": info["score"],
                    "level": info["nivel"],
                    "icon": info["icone"],
                    "analysis": cache_analise
                }
            
            dados = await orquestrar_coleta_dados_url(url_final)
            analise = await analisar_com_ia(url_final, dados, origem="api", metadados=meta)
            info = extrair_veredito_e_score(analise)
            
            return {
                "status": "success",
                "cached": False,
                "type": "url",
                "url": url,
                "resolved_url": url_final,
                "verdict": info["veredito"],
                "score": info["score"],
                "level": info["nivel"],
                "icon": info["icone"],
                "analysis": analise
            }
        except Exception as e:
            registrar_log(f"Erro na análise de URL da API: {e}", "ERRO")
            raise HTTPException(status_code=500, detail=f"Erro interno na análise da URL: {str(e)}")
    else:
        # 2. Trata Texto Puro (SMS, WhatsApp, etc)
        try:
            cache_analise, _ = checar_cache_analise(texto)
            if cache_analise:
                info = extrair_veredito_e_score(cache_analise)
                return {
                    "status": "success",
                    "cached": True,
                    "type": "text",
                    "verdict": info["veredito"],
                    "score": info["score"],
                    "level": info["nivel"],
                    "icon": info["icone"],
                    "analysis": cache_analise
                }
                
            analise = await asyncio.to_thread(analisar_texto_ia, texto, "api", meta)
            info = extrair_veredito_e_score(analise)
            
            return {
                "status": "success",
                "cached": False,
                "type": "text",
                "verdict": info["veredito"],
                "score": info["score"],
                "level": info["nivel"],
                "icon": info["icone"],
                "analysis": analise
            }
        except Exception as e:
            registrar_log(f"Erro na análise de texto da API: {e}", "ERRO")
            raise HTTPException(status_code=500, detail=f"Erro interno na análise do texto: {str(e)}")

# --- Rota Específica para Texto / SMS ---

@app.post("/api/v1/analyze-text")
async def analyze_text(data: AnalyzeTextRequest, api_key: Any = Depends(get_api_key)):
    """
    Analisa texto de mensagens suspeitas (SMS, WhatsApp, Notificações Judiciais, etc).
    """
    texto = data.text.strip()
    if not texto:
        raise HTTPException(status_code=400, detail="Texto não informado.")
        
    meta = {"origem": data.source or "API (Texto)"}
    try:
        cache_analise, _ = checar_cache_analise(texto)
        if cache_analise:
            info = extrair_veredito_e_score(cache_analise)
            return {
                "status": "success",
                "cached": True,
                "verdict": info["veredito"],
                "score": info["score"],
                "level": info["nivel"],
                "icon": info["icone"],
                "analysis": cache_analise
            }
            
        analise = await asyncio.to_thread(analisar_texto_ia, texto, "api", meta)
        info = extrair_veredito_e_score(analise)
        return {
            "status": "success",
            "cached": False,
            "verdict": info["veredito"],
            "score": info["score"],
            "level": info["nivel"],
            "icon": info["icone"],
            "analysis": analise
        }
    except Exception as e:
        registrar_log(f"Erro analyze-text API: {e}", "ERRO")
        raise HTTPException(status_code=500, detail=f"Erro ao analisar mensagem: {str(e)}")

# --- Rota para Upload de Imagens (OCR) e PDFs Jurídicos ---

@app.post("/api/v1/analyze-file")
async def analyze_file(
    file: UploadFile = File(...),
    source: Optional[str] = Query("mobile_app"),
    api_key: Any = Depends(get_api_key)
):
    """
    Analisa imagens (prints de tela, fotos de comprovantes) e PDFs de documentos suspeitos com Visão Computacional / OCR.
    """
    # Validação do tipo de arquivo
    mime_type = file.content_type or "image/jpeg"
    if not (mime_type.startswith("image/") or mime_type == "application/pdf"):
        raise HTTPException(status_code=400, detail="Formato não suportado. Envie uma imagem (PNG, JPG, WEBP) ou PDF.")
        
    # Limita tamanho do arquivo em memória (20MB)
    max_size = 20 * 1024 * 1024
    file_bytes = await file.read()
    if len(file_bytes) > max_size:
        raise HTTPException(status_code=400, detail="Arquivo excede o limite máximo permitido de 20MB.")
        
    meta = {"origem": source or "API (Arquivo)", "filename": file.filename}
    try:
        analise = await analisar_arquivo_ia(file_bytes, mime_type, origem="api", metadados=meta)
        info = extrair_veredito_e_score(analise)
        return {
            "status": "success",
            "filename": file.filename,
            "mime_type": mime_type,
            "verdict": info["veredito"],
            "score": info["score"],
            "level": info["nivel"],
            "icon": info["icone"],
            "analysis": analise
        }
    except Exception as e:
        registrar_log(f"Erro analyze-file API: {e}", "ERRO")
        raise HTTPException(status_code=500, detail=f"Falha no processamento do arquivo: {str(e)}")

# --- Verificação de Vazamento de Senhas (Have I Been Pwned) ---

@app.post("/api/v1/check-password")
async def check_password_leak(data: PasswordCheckRequest, api_key: Any = Depends(get_api_key)):
    """
    Verifica se uma senha foi exposta em vazamentos mundiais usando k-anonymity (pyhibp).
    """
    if not data.password:
        raise HTTPException(status_code=400, detail="Senha não informada.")
        
    try:
        is_breached = await checar_senha_vazada(data.password)
        return {
            "status": "success",
            "breached": is_breached,
            "message": "⚠️ Senha encontrada em vazamentos de dados conhecidos! Altere imediatamente." if is_breached else "✅ Senha não encontrada nos principais vazamentos públicos."
        }
    except Exception as e:
        registrar_log(f"Erro check-password API: {e}", "ERRO")
        raise HTTPException(status_code=500, detail=f"Erro ao consultar base de vazamentos: {str(e)}")

# --- Validação de E-mail e Domínio ---

@app.post("/check-email")
def check_email(data: EmailRequest, api_key: Any = Depends(get_api_key)):
    """
    Verifica se o formato do e-mail é válido e se o domínio aceita e-mails.
    """
    try:
        valid = validate_email(data.email, check_deliverability=True)
        return {
            "status": "valid",
            "email_normalized": valid.normalized,
            "domain": valid.domain
        }
    except EmailNotValidError as e:
        return {"status": "invalid", "reason": str(e)}

@app.post("/check-domain")
def check_domain(data: DomainRequest, api_key: Any = Depends(get_api_key)):
    """
    Realiza uma consulta WHOIS básica no domínio.
    """
    try:
        domain_info = whois.whois(data.domain)
        return {
            "domain": data.domain,
            "registrar": domain_info.registrar,
            "creation_date": domain_info.creation_date,
            "expiration_date": domain_info.expiration_date
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro ao consultar domínio: {str(e)}")

# --- Feedback e Estatísticas do Sistema ---

@app.post("/api/v1/feedback")
def submit_feedback(data: FeedbackRequest, api_key: Any = Depends(get_api_key)):
    try:
        salvar_feedback(data.input_usuario, data.output_ia, data.avaliacao)
        return {"status": "success", "message": "Feedback registrado com sucesso!"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao registrar feedback: {str(e)}")

@app.get("/api/v1/stats")
def get_stats(api_key: Any = Depends(get_api_key)):
    db = SessionLocal()
    try:
        total_analises = db.query(DatasetItem).count()
        total_usuarios = db.query(Usuario).count()
        total_feedbacks = db.query(Feedback).count()
        
        return {
            "total_analises": total_analises,
            "total_usuarios": total_usuarios,
            "total_feedbacks": total_feedbacks,
            "status": "operacional"
        }
    except Exception as e:
        return {
            "total_analises": 0,
            "total_usuarios": 0,
            "total_feedbacks": 0,
            "erro": str(e)
        }
    finally:
        db.close()

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
