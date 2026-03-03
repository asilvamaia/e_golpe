from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
import whois
from email_validator import validate_email, EmailNotValidError
import os
from dotenv import load_dotenv
import asyncio
from core import checar_cache_analise, orquestrar_coleta_dados_url, analisar_com_ia, extrair_url

# Carrega variáveis de ambiente
load_dotenv()

from fastapi.middleware.cors import CORSMiddleware

API_KEY_NAME = "x-api-key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def get_api_key(api_key_header: str = Security(api_key_header)):
    expected_api_key = os.environ.get("API_KEY_SECRET")
    expected_api_key = expected_api_key.strip() if expected_api_key else None
    # Se a variável API_KEY_SECRET não estiver configurada no Railway, a API fica 'aberta' temporariamente (fallback)
    if not expected_api_key:
        return True
    
    if api_key_header == expected_api_key:
        return api_key_header
        
    raise HTTPException(
        status_code=403, 
        detail="Acesso Negado: Chave de API (x-api-key) ausente ou inválida."
    )

app = FastAPI(title="Guardian Bot API", description="API para detecção de fraudes e verificação de segurança.")

# Adiciona o middleware CORS para permitir que a extensão de navegador consiga se conectar à API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite de qualquer origem
    allow_credentials=True,
    allow_methods=["*"],  # Permite POST, GET, OPTIONS, etc
    allow_headers=["*"],
)

# Modelos de dados para entrada (Request Body)
class AnalyzeRequest(BaseModel):
    text: str
    
class EmailRequest(BaseModel):
    email: str

class DomainRequest(BaseModel):
    domain: str

@app.get("/")
def home():
    return {"message": "Guardian Bot está ativo!", "status": "online"}

@app.post("/check-email")
def check_email(data: EmailRequest, api_key: str = Depends(get_api_key)):
    """
    Verifica se o formato do e-mail é válido e se o domínio aceita e-mails.
    """
    try:
        # check_deliverability=True verifica se o domínio MX existe
        valid = validate_email(data.email, check_deliverability=True)
        return {
            "status": "valid",
            "email_normalized": valid.normalized,
            "domain": valid.domain
        }
    except EmailNotValidError as e:
        return {"status": "invalid", "reason": str(e)}

@app.post("/check-domain")
def check_domain(data: DomainRequest, api_key: str = Depends(get_api_key)):
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

@app.post("/api/v1/analyze")
async def analyze_content(data: AnalyzeRequest, api_key: str = Depends(get_api_key)):
    """
    Analisa um link ou texto recebido usando a IA e as APIs de segurança.
    """
    texto = data.text
    url = extrair_url(texto)
    meta = {"origem": "API"}
    
    if url:
        try:
            cache_analise, _ = checar_cache_analise(url)
            if cache_analise:
                return {"status": "success", "cached": True, "analysis": cache_analise}
            
            dados = await orquestrar_coleta_dados_url(url)
            analise = await analisar_com_ia(url, dados, origem="api", metadados=meta)
            
            return {"status": "success", "cached": False, "analysis": analise}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Layer interno falhou: {e}")
    else:
        # Se for só texto
        raise HTTPException(status_code=400, detail="Apenas URLs são suportadas nesta versão da API.")

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    # Para deploy, o runner padrão do Railway lerá esta variável
    uvicorn.run(app, host="0.0.0.0", port=port)
