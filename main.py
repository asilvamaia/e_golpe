from fastapi import FastAPI, HTTPException, Security, Depends, File, UploadFile, Query, Request
from fastapi.responses import StreamingResponse
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import whois
from email_validator import validate_email, EmailNotValidError
import os
import secrets
import base64
import hashlib
import hmac
import io
import json
import zipfile
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
from database.models import DatasetItem, Feedback, Usuario, DomainList

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
    allow_origin_regex=os.environ.get(
        "CORS_ALLOWED_ORIGIN_REGEX",
        r"^(chrome-extension|moz-extension)://.+$",
    ),
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

class MasterLoginRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=256)

class MasterDomainRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)
    list_type: str = Field(..., pattern="^(whitelist|blacklist)$")

MASTER_COOKIE_HEADER = "x-master-session"
master_session_header = APIKeyHeader(name=MASTER_COOKIE_HEADER, auto_error=False)
_login_attempts: Dict[str, List[float]] = {}

def _master_secret() -> bytes:
    value = os.environ.get("ADMIN_SESSION_SECRET") or os.environ.get("API_KEY_SECRET")
    if not value or len(value) < 24:
        raise HTTPException(status_code=503, detail="Acesso administrativo não configurado.")
    return value.encode("utf-8")

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def _issue_master_session() -> str:
    payload = {"exp": int(time.time()) + 8 * 60 * 60, "nonce": secrets.token_urlsafe(16)}
    encoded = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = _b64url(hmac.new(_master_secret(), encoded.encode("ascii"), hashlib.sha256).digest())
    return f"{encoded}.{signature}"

def require_master_session(token: Optional[str] = Security(master_session_header)):
    if not token or "." not in token:
        raise HTTPException(status_code=401, detail="Sessão administrativa necessária.")
    encoded, signature = token.rsplit(".", 1)
    expected = _b64url(hmac.new(_master_secret(), encoded.encode("ascii"), hashlib.sha256).digest())
    if not secrets.compare_digest(signature, expected):
        raise HTTPException(status_code=401, detail="Sessão inválida.")
    try:
        padding = "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded + padding))
        if int(payload.get("exp", 0)) <= int(time.time()):
            raise ValueError("expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Sessão expirada.")
    return True

def _verify_master_password(password: str) -> bool:
    password_hash = (os.environ.get("ADMIN_PASS_HASH") or "").strip()
    if not password_hash:
        return False
    try:
        import bcrypt
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        return False

def _serialize_datetime(value):
    return value.isoformat() if value else None

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

# --- Administração protegida ---

@app.post("/api/v1/master/login")
def master_login(data: MasterLoginRequest, request: Request, api_key: Any = Depends(get_api_key)):
    client = request.client.host if request.client else "unknown"
    now = time.time()
    attempts = [stamp for stamp in _login_attempts.get(client, []) if now - stamp < 15 * 60]
    if len(attempts) >= 5:
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde 15 minutos.")
    if not _verify_master_password(data.password):
        attempts.append(now)
        _login_attempts[client] = attempts
        time.sleep(0.6)
        raise HTTPException(status_code=401, detail="Credenciais inválidas.")
    _login_attempts.pop(client, None)
    return {"status": "authenticated", "token": _issue_master_session(), "expires_in": 8 * 60 * 60}

@app.get("/api/v1/master/session")
def master_session(_: Any = Depends(require_master_session), api_key: Any = Depends(get_api_key)):
    return {"authenticated": True}

@app.get("/api/v1/master/summary")
def master_summary(_: Any = Depends(require_master_session), api_key: Any = Depends(get_api_key)):
    db = SessionLocal()
    try:
        return {
            "analyses": db.query(DatasetItem).count(),
            "feedbacks": db.query(Feedback).count(),
            "whitelist": db.query(DomainList).filter(DomainList.list_type == "whitelist").count(),
            "blacklist": db.query(DomainList).filter(DomainList.list_type == "blacklist").count(),
        }
    finally:
        db.close()

@app.get("/api/v1/master/dataset")
def master_dataset(page: int = Query(1, ge=1), limit: int = Query(25, ge=1, le=100), _: Any = Depends(require_master_session), api_key: Any = Depends(get_api_key)):
    db = SessionLocal()
    try:
        total = db.query(DatasetItem).count()
        rows = db.query(DatasetItem).order_by(DatasetItem.id.desc()).offset((page - 1) * limit).limit(limit).all()
        return {"total": total, "page": page, "items": [{"id": row.id, "timestamp": _serialize_datetime(row.timestamp), "analysis": row.analise_modelo, "metadata": row.metadados, "technical_data": row.dados_tecnicos} for row in rows]}
    finally:
        db.close()

@app.get("/api/v1/master/feedbacks")
def master_feedbacks(page: int = Query(1, ge=1), limit: int = Query(25, ge=1, le=100), _: Any = Depends(require_master_session), api_key: Any = Depends(get_api_key)):
    db = SessionLocal()
    try:
        total = db.query(Feedback).count()
        rows = db.query(Feedback).order_by(Feedback.id.desc()).offset((page - 1) * limit).limit(limit).all()
        return {"total": total, "page": page, "items": [{"id": row.id, "timestamp": _serialize_datetime(row.timestamp), "input": row.input_usuario, "output": row.output_ia, "rating": row.avaliacao} for row in rows]}
    finally:
        db.close()

@app.get("/api/v1/master/domains")
def master_domains(list_type: str = Query(..., pattern="^(whitelist|blacklist)$"), _: Any = Depends(require_master_session), api_key: Any = Depends(get_api_key)):
    db = SessionLocal()
    try:
        rows = db.query(DomainList).filter(DomainList.list_type == list_type).order_by(DomainList.id.desc()).all()
        return {"items": [{"id": row.id, "domain": row.domain, "list_type": row.list_type, "added_at": _serialize_datetime(row.added_at)} for row in rows]}
    finally:
        db.close()

@app.post("/api/v1/master/domains")
def master_add_domain(data: MasterDomainRequest, _: Any = Depends(require_master_session), api_key: Any = Depends(get_api_key)):
    domain = data.domain.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    if not domain or "." not in domain or any(char.isspace() for char in domain):
        raise HTTPException(status_code=400, detail="Domínio inválido.")
    db = SessionLocal()
    try:
        existing = db.query(DomainList).filter(DomainList.domain == domain).first()
        if existing:
            existing.list_type = data.list_type
        else:
            db.add(DomainList(domain=domain, list_type=data.list_type))
        db.commit()
        return {"status": "saved", "domain": domain, "list_type": data.list_type}
    except Exception:
        db.rollback()
        raise HTTPException(status_code=400, detail="Não foi possível salvar o domínio.")
    finally:
        db.close()

@app.delete("/api/v1/master/domains/{domain_id}")
def master_delete_domain(domain_id: int, _: Any = Depends(require_master_session), api_key: Any = Depends(get_api_key)):
    db = SessionLocal()
    try:
        row = db.query(DomainList).filter(DomainList.id == domain_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Domínio não encontrado.")
        db.delete(row)
        db.commit()
        return {"status": "deleted"}
    finally:
        db.close()

@app.get("/api/v1/master/logs")
def master_logs(_: Any = Depends(require_master_session), api_key: Any = Depends(get_api_key)):
    try:
        from core import LOG_FILE
        if not LOG_FILE.exists():
            return {"lines": []}
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as handle:
            return {"lines": handle.readlines()[-200:]}
    except Exception:
        return {"lines": []}

@app.get("/api/v1/master/backup")
def master_backup(_: Any = Depends(require_master_session), api_key: Any = Depends(get_api_key)):
    buffer = io.BytesIO()
    db = SessionLocal()
    try:
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            datasets = db.query(DatasetItem).all()
            feedbacks = db.query(Feedback).all()
            domains = db.query(DomainList).all()
            archive.writestr("dataset.json", json.dumps([{"id": row.id, "timestamp": _serialize_datetime(row.timestamp), "analysis": row.analise_modelo, "metadata": row.metadados, "technical_data": row.dados_tecnicos} for row in datasets], ensure_ascii=False, default=str))
            archive.writestr("feedbacks.json", json.dumps([{"id": row.id, "timestamp": _serialize_datetime(row.timestamp), "input": row.input_usuario, "output": row.output_ia, "rating": row.avaliacao} for row in feedbacks], ensure_ascii=False, default=str))
            archive.writestr("domains.json", json.dumps([{"id": row.id, "domain": row.domain, "list_type": row.list_type, "added_at": _serialize_datetime(row.added_at)} for row in domains], ensure_ascii=False, default=str))
    finally:
        db.close()
    buffer.seek(0)
    filename = f"egolpe_backup_{time.strftime('%Y%m%d_%H%M')}.zip"
    return StreamingResponse(buffer, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"})

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
