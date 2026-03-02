import os
import re
import time
import json
import ssl
import socket
import requests
import whois
import base64
import threading
import difflib
import ipaddress
import logging
import httpx
import asyncio
from urllib.parse import urlparse
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from pathlib import Path
from colorama import init, Fore, Style

# --- ATUALIZAÇÃO DO SDK DO GOOGLE ---
from google import genai
from google.genai import types

from database.db import SessionLocal
from database.models import Usuario, DatasetItem, Feedback, DomainList, AmeacaCache

# --- 1. CONFIGURAÇÃO E CONSTANTES ---

init(autoreset=True)

pasta_atual = Path(__file__).parent
arquivo_env = pasta_atual / ".env"
load_dotenv(dotenv_path=arquivo_env if arquivo_env.exists() else None)

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

# --- CHAVES DE API ---
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GOOGLE_SB_KEY = os.getenv("GOOGLE_API_KEY") 
GOOGLE_AI_KEY = os.getenv("GOOGLE_AI_KEY")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")

MAX_CONTENT_SIZE = 1024 * 1024 
REQUEST_TIMEOUT = 10 
FORBIDDEN_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0', '::1']

HOSTS_GRATUITOS_RISCO = ["framer.website", "vercel.app", "herokuapp.com", "netlify.app", "glitch.me", "000webhostapp.com", "firebaseapp.com", "weebly.com", "wixsite.com", "blogspot.com", "wordpress.com", "pages.dev"]
KEYWORDS_RISCO = ["oferta", "promo", "promocao", "desconto", "gratis", "premio", "sorteio", "ganhar", "resgate", "presente", "aniversario", "atendimento", "suporte", "sac", "ajuda", "recuperar", "voos", "passagens", "milhas", "pontos", "clube", "liberado", "pendente", "bloqueado", "acesso", "seguro"]
ALVOS_TYPOSQUATTING = ["google.com", "facebook.com", "instagram.com", "caixa.gov.br", "bb.com.br", "bradesco.com.br", "itau.com.br", "nubank.com.br", "santander.com.br", "correios.com.br", "gov.br", "mercadolivre.com.br", "amazon.com.br", "americanas.com.br", "magalu.com.br", "receita.fazenda.gov.br", "netflix.com", "inss.gov.br", "meu.inss.gov.br", "latam.com", "latamairlines.com", "voegol.com.br", "voeazul.com.br", "giulianaflores.com.br", "cacaushow.com.br", "boticario.com.br"]
WHITELIST_DEFAULT = ["uol.com.br", "globo.com", "g1.globo.com", "google.com", "google.com.br", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com", "x.com", "twitter.com", "terra.com.br", "r7.com", "estadao.com.br", "folha.uol.com.br", "cnnbrasil.com.br", "wikipedia.org", "linkedin.com", "tiktok.com", "amazon.com", "amazon.com.br", "mercadolivre.com.br", "mercadolibre.com", "mercadolibre.com.ar", "mercadolibre.com.mx", "magalu.com.br", "magazineluiza.com.br", "americanas.com.br", "casasbahia.com.br", "pontofrio.com.br", "shopee.com.br", "shopee.com", "aliexpress.com", "shein.com", "ifood.com.br", "rappi.com.br", "giulianaflores.com.br", "cacaushow.com.br", "boticario.com.br", "latam.com", "latamairlines.com", "voegol.com.br", "voeazul.com.br", "decolar.com", "caixa.gov.br", "bb.com.br", "itau.com.br", "bradesco.com.br", "santander.com.br", "nubank.com.br", "inter.co", "bancointer.com.br", "original.com.br", "picpay.com", "mercadopago.com.br", "pagseguro.uol.com.br", "gov.br", "receita.fazenda.gov.br", "correios.com.br", "planalto.gov.br", "inss.gov.br", "meu.inss.gov.br", "detran.sp.gov.br", "tse.jus.br", "bcb.gov.br", "cgi.br", "nic.br", "registro.br", "reclameaqui.com.br", "consumidor.gov.br", "procon.sp.gov.br", "seiden.tech", "dia.com.br", "ifix.com.br"]

INSTRUCOES_SISTEMA = """
Você é o GuardianBot, um especialista em segurança digital. 
Seu objetivo é analisar mensagens e links suspeitos.

### ESTRUTURA DA RESPOSTA:
1. **Veredito:** Inicie estritamente com "Veredito: ALERTA", "Veredito: GOLPE" ou "Veredito: SEGURO" (em negrito).
2. **Score:** A segunda linha deve conter o Nível de Segurança (ex: 🛡️ Nível de Segurança: 100/100).
3. **Saudação Empática:** Acolha o usuário.
4. **Análise:** Explique o cenário.
5. **Ação:** O que fazer.

### REGRAS ESPECÍFICAS:
- **Hospedagem Gratuita:** Se usar Framer/Vercel e pedir dados, é GOLPE.
- **Golpes Financeiros:** Score baixo, Veredito GOLPE.
- **Fake News:** Se alarmista e sem fonte, Veredito ALERTA.
- **Conteúdo Legítimo:** Notícia real/conversa, Veredito SEGURO, Score 100.

### TOM DE VOZ:
- Seja calmo, didático e protetor.
"""

CLIENTE_IA = None
MODELO_NOME = 'gemma-3-27b-it' 

def configurar_ia():
    global CLIENTE_IA
    if not GOOGLE_AI_KEY: 
        registrar_log("Chave da IA não encontrada", "ALERTA")
        return
    
    try:
        CLIENTE_IA = genai.Client(api_key=GOOGLE_AI_KEY)
        registrar_log(f"IA conectada (Cliente iniciado): {MODELO_NOME}", "INFO")
    except Exception as e:
        registrar_log(f"Falha ao iniciar cliente IA: {e}", "ALERTA")

# --- 2. GERENCIAMENTO DE LISTAS ---

def carregar_listas_seguranca():
    db = SessionLocal()
    try:
        whitelist_records = db.query(DomainList.domain).filter(DomainList.list_type == 'whitelist').all()
        blacklist_records = db.query(DomainList.domain).filter(DomainList.list_type == 'blacklist').all()
        
        whitelist = [r[0] for r in whitelist_records]
        blacklist = [r[0] for r in blacklist_records]
        return whitelist, blacklist
    finally:
        db.close()

# --- 3. FUNÇÕES BÁSICAS ---

def registrar_usuario(user_id):
    db = SessionLocal()
    try:
        if not db.query(Usuario).filter(Usuario.user_id == str(user_id)).first():
            db.add(Usuario(user_id=str(user_id)))
            db.commit()
            registrar_log(f"Novo usuário registrado no banco: {user_id}", "INFO")
    finally:
        db.close()

def extrair_url(texto):
    url_pattern = re.compile(r'(?:http[s]?://)?(?:www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?')
    urls = url_pattern.findall(texto)
    valid_urls = [u for u in urls if "." in u] 
    return valid_urls[0] if valid_urls else None

def limpar_dominio(url):
    if not url: return ""
    parts = url.split("://")
    domain = parts[-1].split("/")[0].split(":")[0]
    if domain.startswith("www."): domain = domain[4:]
    return domain.lower()

def salvar_no_dataset(dados_entrada, analise_ia, metadados=None):
    db = SessionLocal()
    try:
        novo_item = DatasetItem(
            dados_tecnicos=dados_entrada,
            analise_modelo=analise_ia,
            metadados=metadados or {"origem": "Desconhecida"}
        )
        db.add(novo_item)
        db.commit()
    except Exception as e:
        registrar_log(f"Erro ao salvar dataset no DB: {e}", "ERRO")
    finally:
        db.close()

def salvar_feedback(texto_usuario, resposta_ia, avaliacao):
    db = SessionLocal()
    try:
        novo_feedback = Feedback(
            input_usuario=texto_usuario,
            output_ia=resposta_ia,
            avaliacao=avaliacao
        )
        db.add(novo_feedback)
        db.commit()
        registrar_log(f"Novo feedback recebido e salvo no BD: {avaliacao}", "INFO")
    except Exception as e:
        registrar_log(f"Erro ao salvar feedback no DB: {e}", "ERRO")
    finally:
        db.close()

def checar_cache_analise(input_str, max_horas=24):
    db = SessionLocal()
    try:
        limite = datetime.utcnow() - timedelta(hours=max_horas)
        recentes = db.query(DatasetItem).filter(DatasetItem.timestamp >= limite).order_by(DatasetItem.timestamp.desc()).all()
        for item in recentes:
            if item.dados_tecnicos and item.dados_tecnicos.get('input') == input_str:
                return item.analise_modelo, item.dados_tecnicos
        return None, None
    except Exception as e:
        registrar_log(f"Erro DB Cache: {e}", "ERRO")
        return None, None
    finally:
        db.close()

def desencurtar_link(url):
    if not url.startswith("http"): url = "http://" + url
    try:
        resp = requests.head(url, allow_redirects=True, timeout=5)
        url_final = resp.url
        if limpar_dominio(url) != limpar_dominio(url_final): return url_final, True
        return url_final, False
    except: return url, False

def normalizar_url_db(url):
    url_limpa = url.lower().strip()
    url_limpa = url_limpa.replace("https://", "").replace("http://", "")
    if url_limpa.startswith("www."): url_limpa = url_limpa[4:]
    return url_limpa.rstrip("/")

# --- 4. FUNÇÕES TÉCNICAS E APIS ---

def validar_seguranca_url(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'): return False, "Protocolo inválido.", url
        hostname = parsed.hostname
        if not hostname: return False, "Endereço inválido.", url
        
        if hostname in FORBIDDEN_HOSTS: return False, "Endereço Proibido (Localhost).", url
        
        try: 
            infos = socket.getaddrinfo(hostname, None)
            for item in infos:
                ip_addr = item[4][0]
                try:
                    ip_obj = ipaddress.ip_address(ip_addr)
                    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local:
                         return False, f"Acesso negado a Rede Interna/Protegida: {ip_addr}", url
                except ValueError: continue

            return True, None, url
        except socket.gaierror:
            if not hostname.startswith("www."):
                new_hostname = "www." + hostname
                new_url = url.replace(hostname, new_hostname, 1)
                try:
                    infos = socket.getaddrinfo(new_hostname, None)
                    return True, "Auto: WWW added", new_url
                except: pass
            
            return False, "DNS_FAIL: Domínio não encontrado ou offline.", url
            
    except Exception as e: return False, f"Erro: {str(e)}", url

def checar_ssl(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname 
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return f"Emitido por: {dict(x[0] for x in cert['issuer']).get('commonName')}"
    except: return "Sem HTTPS/Erro SSL"

def checar_typosquatting(url):
    domain = limpar_dominio(url)
    alertas = []
    for alvo in ALVOS_TYPOSQUATTING:
        if domain == alvo: continue
        if difflib.SequenceMatcher(None, domain, alvo).ratio() > 0.8: alertas.append(f"Parece '{alvo}'")
    return alertas if alertas else "Não"

def checar_idade_dominio(url):
    try:
        d = whois.whois(limpar_dominio(url))
        if d.text and "no match" in d.text.lower(): return "DOMINIO INEXISTENTE"
        date = d.creation_date
        if isinstance(date, list): date = date[0]
        if not date: return "Data Desconhecida"
        if date.tzinfo: date = date.replace(tzinfo=None)
        return f"{(datetime.now() - date).days} dias"
    except: return "Erro Whois"

async def baixar_conteudo_seguro(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    try:
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.get(url, headers=headers, timeout=REQUEST_TIMEOUT, follow_redirects=True)
            # Lê apenas os x primeiros bytes e decodifica para evitar travar a ram
            content = response.content[:MAX_CONTENT_SIZE + 1].decode('utf-8', errors='ignore')
            return content, str(response.url)
    except Exception as e: return None, str(e)

async def analisar_conteudo_site(url):
    if not url.startswith("http"): url = "http://" + url
    html_content, info_extra = await baixar_conteudo_seguro(url)
    if html_content is None: return {"status": "Erro", "detalhe": info_extra}
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        titulo = soup.title.string if soup.title else "Sem título"
        meta_desc = ""
        meta_tag = soup.find('meta', attrs={'name': 'description'}) or soup.find('meta', property='og:description')
        if meta_tag: meta_desc = meta_tag.get('content', '')
        for script in soup(["script", "style"]): script.extract()
        texto_corpo = soup.get_text(separator=' ', strip=True)[:2500]
        resumo_final = f"DESCRIÇÃO DO SITE (SEO): {meta_desc} | CONTEÚDO VISÍVEL: {texto_corpo}"
        return {"url_final": info_extra, "titulo": titulo, "conteudo_resumo": resumo_final}
    except Exception as e: return {"status": "Erro", "detalhe": str(e)}

# --- APIs EXTERNAS ---

def checar_google_safebrowsing(url): return "Não Verificado" if not GOOGLE_SB_KEY else "Limpo (Simulação)"

async def checar_virustotal(url):
    if not VIRUSTOTAL_KEY: return "Não Verificado (Falta API Key)"
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VIRUSTOTAL_KEY, "accept": "application/json"}
        
        async with httpx.AsyncClient() as client:
            response = await client.get(endpoint, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            if malicious > 0:
                return f"⚠️ DETECTADO: {malicious} alertas de segurança (VirusTotal)."
            elif suspicious > 0:
                return f"⚠️ Suspeito: {suspicious} alertas (VirusTotal)."
            else:
                return "Sem Detecções (Limpo no VirusTotal)"
                
        elif response.status_code == 404:
            return "Sem histórico no VirusTotal (URL Nova)"
        else:
            return f"Erro VT ({response.status_code})"
    except Exception as e:
        registrar_log(f"Erro VirusTotal: {e}", "ALERTA")
        return "Erro na conexão com VirusTotal"

async def checar_urlscan(url):
    if not URLSCAN_KEY: return "Não Verificado (Falta API)"
    domain = limpar_dominio(url)
    try:
        headers = {'API-Key': URLSCAN_KEY, 'Content-Type': 'application/json'}
        params = {'q': f'domain:{domain}', 'size': 1}
        async with httpx.AsyncClient() as client:
            r = await client.get("https://urlscan.io/api/v1/search/", headers=headers, params=params, timeout=5)
        data = r.json()
        if data.get('results'):
            last_scan = data['results'][0]
            verdict = last_scan.get('verdicts', {}).get('overall', {})
            if verdict.get('malicious'): return "DETECTADO: MALICIOSO"
            elif verdict.get('score', 0) > 0: return f"Suspeito (Score: {verdict.get('score')})"
        return "Limpo (Histórico)"
    except: return "Erro URLScan"

# --- 5. SISTEMA AGREGADOR ---
CACHE_AMEACAS = set()
ULTIMO_UPDATE_AMEACAS = 0

def atualizar_bases_ameacas():
    global CACHE_AMEACAS, ULTIMO_UPDATE_AMEACAS
    urls_unificadas = set()
    agora = time.time()
    
    db = SessionLocal()
    try:
        # Check cache freshness in-memory (every 2 hours)
        if agora - ULTIMO_UPDATE_AMEACAS < 7200 and CACHE_AMEACAS:
            return
            
        if not CACHE_AMEACAS:
            registros = db.query(AmeacaCache.url).all()
            if registros:
                CACHE_AMEACAS = set(r[0] for r in registros)
                registrar_log(f"Cache de ameaças carregado do DB: {len(CACHE_AMEACAS)} URLs", "INFO")
                
        # If cache in DB is older than 2 hours or empty, we fetch
        # For simplicity, we just fetch anyway if memory is stale.
    finally:
        db.close()

    registrar_log("Iniciando atualização de bases de phishing...", "INFO")
    headers = {'User-Agent': 'Mozilla/5.0'}

    try:
        r = requests.get("https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt", headers=headers, timeout=20)
        if r.status_code == 200:
            for l in r.text.splitlines():
                if l.strip(): urls_unificadas.add(normalizar_url_db(l.strip()))
    except: pass

    try:
        r = requests.get("https://openphish.com/feed.txt", headers=headers, timeout=20)
        if r.status_code == 200:
            for l in r.text.splitlines():
                if l.strip(): urls_unificadas.add(normalizar_url_db(l.strip()))
    except: pass

    try:
        r = requests.get("http://data.phishtank.com/data/online-valid.json", headers=headers, timeout=30, stream=True)
        if r.status_code == 200:
            dados = r.json()
            for entry in dados: urls_unificadas.add(normalizar_url_db(entry['url']))
    except: pass

    if urls_unificadas:
        CACHE_AMEACAS = urls_unificadas
        ULTIMO_UPDATE_AMEACAS = time.time()
        db = SessionLocal()
        try:
            db.query(AmeacaCache).delete()
            batch = [{"url": d} for d in CACHE_AMEACAS]
            db.bulk_insert_mappings(AmeacaCache, batch)
            db.commit()
            registrar_log(f"Base de ameaças DB atualizada: {len(CACHE_AMEACAS)} URLs", "INFO")
        except Exception as e:
            db.rollback()
            registrar_log(f"Erro ao salvar DB de Ameaças: {e}", "ERRO")
        finally:
            db.close()

# Background thread is disabled by default on startup to prevent Memory Exhaustion (OOM) on free cloud tiers.
# threading.Thread(target=atualizar_bases_ameacas, daemon=True).start()

def checar_bases_phishing(url):
    url_norm = normalizar_url_db(url)
    
    # Check in-memory first (if manually loaded or small)
    global CACHE_AMEACAS
    if CACHE_AMEACAS and url_norm in CACHE_AMEACAS:
        return "DETECTADO: PHISHING CONFIRMADO (Base Global)"
        
    # Query database directly to preserve RAM instead of loading all entries to memory
    db = SessionLocal()
    try:
        match = db.query(AmeacaCache).filter(AmeacaCache.url == url_norm).first()
        if match:
             return "DETECTADO: PHISHING CONFIRMADO (Base Global)"
    finally:
        db.close()
        
    return "Limpo (Não listado)"

checar_phishtank = checar_bases_phishing

# --- 6. LÓGICA DE SCORE E ANÁLISE ---

def detecting_topicos_sensiveis(texto_site, url=""):
    texto_lower = texto_site.lower()
    domain_lower = limpar_dominio(url) if url else ""
    if re.search(r'\b(mãe|pai|vó|vô)\b.+\b(troquei|novo)\b.+\b(número|celular|agenda)\b', texto_lower): return "GOLPE_PARENTE", "Golpe do Falso Parente/Número Novo."
    if re.search(r'\b(inss|prova de vida|benefício|aposentadoria)\b.+\b(bloqueado|suspenso|atualiz|revisão)\b', texto_lower):
        if "gov.br" not in domain_lower: return "GOLPE_INSS", "Tentativa de Golpe do INSS."
    if re.search(r'\b(valores a receber|dinheiro esquecido|precatório|resgate)\b.+\b(cpf|consultar|liberado)\b', texto_lower):
        if "bcb.gov.br" not in domain_lower and "gov.br" not in domain_lower: return "GOLPE_FINANCEIRO", "Site falso de Valores a Receber."
    if re.search(r'\b(aniversário|presente|brinde)\b.+\b(taxa|frete|entrega)\b', texto_lower): return "GOLPE_ANIVERSARIO", "Golpe do Presente de Aniversário."
    if re.search(r'\b(cura|milagre|reverter|fim da|acabar com)\b.+\b(diabetes|visão|surdez|cancer|impotência)\b', texto_lower): return "FAKE_SAUDE", "Promessa de Cura Milagrosa."
    regex_aposta = r'\b(bet|bets|betano|bet365|pixbet|sportingbet|tigrinho|aviator|aposta|odds|cotação|cassino|slot|jackpot)\b'
    if re.search(r'\b(xxx|porn|sexo|amador|videos x)\b', texto_lower) or "18+" in texto_lower: return "ADULTO", "Site de Conteúdo Adulto."
    if re.search(regex_aposta, texto_lower) or ("bet" in domain_lower and "jogo" in texto_lower): return "APOSTAS", "Site de Apostas/Jogos de Azar."
    return None, None

detectar_topicos_sensiveis = detecting_topicos_sensiveis

def calcular_score_risco(dados, domain_clean):
    whitelist, blacklist = carregar_listas_seguranca()
    score = 100
    fatores = []
    
    for safe in whitelist:
        if domain_clean == safe or domain_clean.endswith("." + safe): return 100, "OFICIAL", "green", []
    
    for bad in blacklist:
        if bad in domain_clean: 
            score -= 100
            fatores.append("Sistema de Segurança: Domínio identificado em lista de ameaças ativas (-100)")

    if "Limpo" not in dados.get('google', 'Limpo'): score -= 100; fatores.append("Google Safe Browsing: Detectado como Perigoso (-100)")
    if "DETECTADO" in dados.get('phishtank', ''): score -= 100; fatores.append("Base de Phishing: URL CONFIRMADA COMO GOLPE (-100)")
    if "MALICIOSO" in dados.get('urlscan', ''): score -= 100; fatores.append("URLScan.io: Detectado como MALICIOSO (-100)")
    
    # Lógica atualizada para VirusTotal
    if "Sem Detecções" not in dados.get('vt', 'Sem Detecções'): score -= 50; fatores.append("VirusTotal: Alertas de antivírus encontrados (-50)")
    
    if dados.get('typosquatting', 'Não') != "Não": score -= 60; fatores.append("Nome do site imita uma marca famosa (-60)")
    
    if any(h in domain_clean for h in HOSTS_GRATUITOS_RISCO):
        score -= 40; fatores.append(f"⚠️ Hospedagem Gratuita de Alto Risco ({domain_clean.split('.')[-2]}). Cuidado com clones.")

    palavras_encontradas = [k for k in KEYWORDS_RISCO if k in domain_clean]
    if palavras_encontradas: score -= 35; fatores.append(f"⚠️ Domínio contém palavras suspeitas: {', '.join(palavras_encontradas)} (-35)")
    
    idade_str = dados.get('idade', '')
    if "dias" in idade_str:
        try:
            dias = int(idade_str.split()[0])
            if dias < 30: score -= 40; fatores.append("Site criado há menos de 1 mês (-40)")
            elif dias < 180: score -= 15; fatores.append("Site novo (menos de 6 meses) (-15)")
            elif dias > 3650: score += 5
        except: pass
    if "Sem HTTPS" in dados.get('ssl', ''): score -= 30; fatores.append("Site sem Cadeado de Segurança (Sem SSL) (-30)")
    
    conteudo = dados.get('conteudo', {}).get('conteudo_resumo', '')
    cat_sensivel, _ = detectar_topicos_sensiveis(conteudo, domain_clean)
    if cat_sensivel:
        if "GOLPE" in cat_sensivel or "FAKE" in cat_sensivel: score -= 50; fatores.append(f"Alerta de Golpe Detectado: {cat_sensivel} (-50)")
        else: score -= 10; fatores.append(f"Conteúdo de Risco: {cat_sensivel} (-10)")
    
    score = max(0, min(100, score))
    if score >= 80: return score, "CONFIÁVEL", "green", fatores
    elif score >= 50: return score, "ATENÇÃO", "orange", fatores
    else: return score, "PERIGO", "red", fatores

def montar_instrucoes_formato(origem, score, classificacao, fatores_risco, alerta_sensivel=None):
    resumo_fatores = "\n".join([f"- {f}" for f in fatores_risco]) if fatores_risco else "- Nenhum problema grave."
    aviso_extra = ""
    if alerta_sensivel == "FAKE_SAUDE": aviso_extra = "ALERTA DE SAÚDE: Promessa de cura milagrosa."
    elif alerta_sensivel == "GOLPE_INSS": aviso_extra = "ALERTA INSS: Governo não manda link por SMS."
    elif alerta_sensivel == "GOLPE_PARENTE": aviso_extra = "ALERTA FAMÍLIA: Ligue para o número antigo."
    
    diretrizes = "DIRETRIZES DE LINGUAGEM: Fale simples e acolhedor (foco em idosos)."
    contexto = f"📊 SCORE: {score}/100\nClassificação: {classificacao}\nProblemas:\n{resumo_fatores}\n{aviso_extra}"
    
    cor_vermelha = False
    if classificacao == "PERIGO" or "FAKE NEWS" in classificacao or score == 0: cor_vermelha = True
    
    if origem == "streamlit":
        cor = ":green"
        if cor_vermelha: cor = ":red"
        elif classificacao in ["ATENÇÃO", "ALERTA"]: cor = ":orange"
        linha1 = f"**Veredito:** {cor}[**{classificacao}**]"
        linha2 = f"🛡️ **Nível de Segurança:** {score}/100"
    else:
        # Fallback para texto puro
        linha1 = f"**Veredito:** {classificacao}"
        linha2 = f"🛡️ **Nível de Segurança:** {score}/100"
        
    return f"{contexto}\n{diretrizes}\n⚠️ REGRA VISUAL:\n1. {linha1}\n2. {linha2}\n3. Pule uma linha."

def gerar_resposta_fallback_sensivel(categoria, origem):
    cor = ":orange[**" if origem == "streamlit" else "**⚠️ "
    end = "**]" if origem == "streamlit" else "**"
    return f"**Veredito:** {cor}ALERTA ({categoria}){end}\n\n**Análise:** Identificamos riscos ({categoria})."

# --- 7. ORQUESTRAÇÃO ---

async def consultar_google_reputacao(dominio):
    api_key = os.getenv("GOOGLE_API_KEY")
    cx = os.getenv("GOOGLE_SEARCH_CX") 
    if not api_key or not cx: return "Não verificado (Falta config API)"
    try:
        query = f'site:reclameaqui.com.br "{dominio}"'
        url = "https://www.googleapis.com/customsearch/v1"
        params = {'key': api_key, 'cx': cx, 'q': query, 'num': 2}
        
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, params=params, timeout=3)
        data = resp.json()
        
        if 'items' in data and len(data['items']) > 0:
            item = data['items'][0]
            return f"🔎 **RECLAME AQUI ENCONTRADO:**\nTítulo: {item.get('title','')}\nLink: {item.get('link','')}"
        else: return "Nenhuma página do Reclame Aqui encontrada para este domínio exato."
    except Exception as e: return f"Erro na consulta de reputação: {str(e)}"

async def consultar_fakenews_google(termo_busca):
    api_key = os.getenv("GOOGLE_API_KEY") 
    if not api_key or not termo_busca or len(termo_busca) < 4: return None
    url = "https://factchecktools.googleapis.com/v1alpha1/claims:search"
    params = {'key': api_key, 'query': termo_busca, 'languageCode': 'pt-BR', 'pageSize': 5}
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(url, params=params, timeout=4)
        dados = r.json()
        
        if "claims" in dados and dados["claims"]:
            dominios_br_extras = ["aosfatos.org", "e-farsas.com", "boatos.org", "afp.com", "lupa.uol.com.br", "reclameaqui.com.br", "estadao.com.br", "projetocomprova.com.br", "g1.globo.com"]
            resultado_backup = None
            for i, claim in enumerate(dados["claims"]):
                review = claim.get("claimReview", [])[0]
                link_prova = review.get("url", "").lower()
                quem_checou = review.get("publisher", {}).get("name", "Agência de Checagem")
                veredito = review.get("textualRating", "Suspeito")
                data_check = claim.get("claimDate", "")[:10]
                msg_formatada = f"🚨 **ALERTA DE FAKE NEWS DETECTADA**\nAgência: **{quem_checou}**\nData: {data_check}\nClassificação: **{veredito}**\n🔗 [Ver Checagem]({link_prova})"
                if i == 0: resultado_backup = msg_formatada
                if any(d in link_prova for d in dominios_br_extras): return msg_formatada
            return resultado_backup 
        return None 
    except Exception as e: return None

async def orquestrar_coleta_dados_url(url_final):
    # Orquestra as chamadas assíncronas
    domain_clean = limpar_dominio(url_final)
    
    t_google = asyncio.to_thread(checar_google_safebrowsing, url_final)
    t_phishtank = asyncio.to_thread(checar_bases_phishing, url_final)
    t_idade = asyncio.to_thread(checar_idade_dominio, url_final)
    t_ssl = asyncio.to_thread(checar_ssl, url_final)
    t_typo = asyncio.to_thread(checar_typosquatting, url_final)
    
    resultados = await asyncio.gather(
        t_google,
        checar_virustotal(url_final),
        t_phishtank,
        checar_urlscan(url_final),
        t_idade,
        t_ssl,
        t_typo,
        analisar_conteudo_site(url_final)
    )
    
    return {
        'google': resultados[0],
        'vt': resultados[1],
        'phishtank': resultados[2],
        'urlscan': resultados[3],
        'idade': resultados[4],
        'ssl': resultados[5],
        'typosquatting': resultados[6],
        'conteudo': resultados[7]
    }

# MODIFICAÇÃO: Lazy Loading e Correção de Input
async def analisar_com_ia(url, dados_completos, origem="streamlit", metadados=None):
    registrar_log(f"Analisando URL: {url}", "INFO")
    dados_completos['input'] = url 
    
    # Lazy Loading: Conecta agora se não estiver conectado
    if not CLIENTE_IA: configurar_ia()
    if not CLIENTE_IA: return "⚠️ IA Offline (Erro de conexão)."

    texto_conteudo = dados_completos['conteudo'].get('conteudo_resumo', '')
    domain_clean = limpar_dominio(url)
    titulo_site = dados_completos['conteudo'].get('titulo', '')
    aviso_fakenews = None 
    info_reputacao = await consultar_google_reputacao(domain_clean)
    cat_sensivel, msg_sensivel = detectar_topicos_sensiveis(texto_conteudo, url)
    score, classificacao, cor_sugerida, fatores = calcular_score_risco(dados_completos, domain_clean)
    instrucoes = montar_instrucoes_formato(origem, score, classificacao, fatores, alerta_sensivel=cat_sensivel)
    prompt = f"""
    {INSTRUCOES_SISTEMA}
    <instrucao_typosquatting>
    Se for site oficial regional (ex: .ar, .mx) ou marca real, RECLASSIFIQUE para SEGURO.
    Se for variação suspeita (ex: ofertas-latam), MANTENHA GOLPE.
    </instrucao_typosquatting>
    Analise:
    Site: {url}
    Título: {titulo_site}
    Resumo: {texto_conteudo}
    SSL: {dados_completos['ssl']}
    Idade: {dados_completos['idade']}
    Reputação: {info_reputacao}
    URLScan: {dados_completos.get('urlscan', 'N/A')}
    {instrucoes}
    Responda em Markdown.
    """
    try:
        # Configuração de segurança usando a nova API
        config_seguranca = types.GenerateContentConfig(
            safety_settings=[
                types.SafetySetting(
                    category=types.HarmCategory.HARM_CATEGORY_HARASSMENT,
                    threshold=types.HarmBlockThreshold.BLOCK_NONE
                ),
                types.SafetySetting(
                    category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                    threshold=types.HarmBlockThreshold.BLOCK_NONE
                ),
                types.SafetySetting(
                    category=types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                    threshold=types.HarmBlockThreshold.BLOCK_NONE
                ),
                types.SafetySetting(
                    category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                    threshold=types.HarmBlockThreshold.BLOCK_NONE
                ),
            ]
        )

        resp = CLIENTE_IA.models.generate_content(
            model=MODELO_NOME,
            contents=prompt,
            config=config_seguranca
        )
        
        # --- VERIFICAÇÃO DE RESPOSTA VAZIA (Correção do Bug) ---
        if not resp.text:
            raise ValueError("Resposta bloqueada pelo filtro de segurança da IA.")
            
        salvar_no_dataset(dados_completos, resp.text, metadados)
        return resp.text
    except Exception as e:
        registrar_log(f"Erro IA URL: {e}", "ERRO")
        
        # FALLBACK PARA QUANDO A IA FALHAR/BLOQUEAR
        motivo_fallback = "Conteúdo bloqueado pela IA ou erro de conexão."
        if cat_sensivel: motivo_fallback = f"Conteúdo sensível detectado: {cat_sensivel}"
        
        fallback_msg = f"""
        **Veredito:** :orange[**ALERTA (SISTEMA)**]

        🛡️ **Nível de Segurança:** {score}/100

        **Análise:**
        A Inteligência Artificial não pôde processar o conteúdo detalhado deste site ({motivo_fallback}).
        
        **Baseado na análise técnica:**
        - Domínio: {domain_clean}
        - Idade: {dados_completos.get('idade')}
        - SSL: {dados_completos.get('ssl')}
        
        **Recomendação:** Tenha cautela extrema.
        """
        salvar_no_dataset(dados_completos, fallback_msg, metadados)
        return fallback_msg

def analisar_texto_ia(texto, origem="streamlit", metadados=None):
    registrar_log(f"Analisando Texto: {texto[:30]}...", "INFO")
    
    if not CLIENTE_IA: configurar_ia()
    if not CLIENTE_IA: return "⚠️ IA Offline (Erro de conexão)."

    aviso_fakenews = consultar_fakenews_google(texto[:150]) 
    cat_sensivel, _ = detectar_topicos_sensiveis(texto, "")
    if aviso_fakenews:
        classificacao = "PERIGO (FAKE NEWS)"; score = 0; fatores = ["Fake News confirmada."]
    elif cat_sensivel:
        classificacao = "ALERTA"; score = 30; fatores = [f"Risco: {cat_sensivel}"]
    else:
        classificacao = "ANÁLISE INICIAL"; score = 60; fatores = []
    
    instrucoes = montar_instrucoes_formato(origem, score, classificacao, fatores, alerta_sensivel=cat_sensivel)
    fake_blk = f"\n<checagem>{aviso_fakenews}</checagem>\nORDEM: É FAKE." if aviso_fakenews else ""
    texto_seguro = texto.replace("<", "").replace(">", "")
    prompt = f"""
    {INSTRUCOES_SISTEMA}
    Analise esta mensagem.
    <instrucao_especial>
    Se for notícia VERDADEIRA, conversa normal ou saudação: Veredito SEGURO, Score 100.
    Se for boato sem fonte: ALERTA (FAKE NEWS), Score Baixo.
    </instrucao_especial>
    Msg: {texto_seguro}
    {fake_blk}
    {instrucoes}
    Responda em Markdown.
    """
    try:
        config_seguranca = types.GenerateContentConfig(
            safety_settings=[
                types.SafetySetting(
                    category=types.HarmCategory.HARM_CATEGORY_HARASSMENT,
                    threshold=types.HarmBlockThreshold.BLOCK_NONE
                ),
                types.SafetySetting(
                    category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                    threshold=types.HarmBlockThreshold.BLOCK_NONE
                ),
                types.SafetySetting(
                    category=types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                    threshold=types.HarmBlockThreshold.BLOCK_NONE
                ),
                types.SafetySetting(
                    category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                    threshold=types.HarmBlockThreshold.BLOCK_NONE
                ),
            ]
        )

        resp = CLIENTE_IA.models.generate_content(
            model=MODELO_NOME,
            contents=prompt,
            config=config_seguranca
        )
        
        if not resp.text:
             raise ValueError("Resposta bloqueada.")

        salvar_no_dataset({"input": texto_seguro}, resp.text, metadados)
        return resp.text
    except Exception as e: return f"Erro IA: {e}"
