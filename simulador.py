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
import itertools
import sys
import difflib
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from pathlib import Path
from colorama import init, Fore, Style
import google.generativeai as genai

# --- CONFIGURAÇÃO INICIAL ---

init(autoreset=True)
pasta_atual = Path(__file__).parent
arquivo_env = pasta_atual / ".env"
load_dotenv(dotenv_path=arquivo_env if arquivo_env.exists() else None)

# Carrega Chaves
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")
GOOGLE_SB_KEY = os.getenv("GOOGLE_API_KEY") 
GOOGLE_AI_KEY = os.getenv("GOOGLE_AI_KEY")

# Arquivos Locais
BLACKLIST_FILE = pasta_atual / "blacklist.txt"
DATASET_FILE = pasta_atual / "dataset_treino.json"

# Lista de Marcas para Typosquatting (Alvos comuns de phishing BR)
ALVOS_TYPOSQUATTING = [
    "google.com", "facebook.com", "instagram.com", "caixa.gov.br", 
    "bb.com.br", "bradesco.com.br", "itau.com.br", "nubank.com.br",
    "santander.com.br", "correios.com.br", "gov.br", "mercadolivre.com.br",
    "amazon.com.br", "americanas.com.br", "magalu.com.br", "receita.fazenda.gov.br"
]

# --- AUTO-CONFIGURAÇÃO DA IA ---
MODELO_IA = None

def configurar_ia():
    global MODELO_IA
    if not GOOGLE_AI_KEY: return
    genai.configure(api_key=GOOGLE_AI_KEY)
    modelos = ['gemini-2.5-flash', 'gemini-flash-latest', 'gemini-2.0-flash', 'gemini-1.5-flash']
    print(f"{Style.DIM}[Config] Conectando à IA...{Style.RESET_ALL}")
    for m in modelos:
        try:
            mod = genai.GenerativeModel(m)
            mod.generate_content("Ping")
            MODELO_IA = mod
            print(f"{Fore.GREEN}[Sucesso] IA conectada: {m}{Style.RESET_ALL}")
            return
        except: continue
    print(f"{Fore.RED}[Erro] IA não conectada.{Style.RESET_ALL}")

if GOOGLE_AI_KEY: configurar_ia()

# Carrega Blacklist
BLACKLIST_DOMAINS = []
if BLACKLIST_FILE.exists():
    with open(BLACKLIST_FILE, "r") as f:
        BLACKLIST_DOMAINS = [line.strip().lower() for line in f if line.strip()]

# --- FUNÇÕES DE SUPORTE (DATASET & VISUAL) ---

def salvar_no_dataset(dados_entrada, analise_ia):
    """Salva a interação em um JSON para treinar o Llama no futuro."""
    entrada = {
        "timestamp": datetime.now().isoformat(),
        "dados_tecnicos": dados_entrada,
        "analise_modelo": analise_ia
    }
    
    # Lê, atualiza e salva (modo append em lista)
    lista_dados = []
    if DATASET_FILE.exists():
        try:
            with open(DATASET_FILE, "r", encoding="utf-8") as f:
                lista_dados = json.load(f)
        except: pass # Se arquivo estiver corrompido, inicia novo
    
    lista_dados.append(entrada)
    
    with open(DATASET_FILE, "w", encoding="utf-8") as f:
        json.dump(lista_dados, f, ensure_ascii=False, indent=2)

class Spinner:
    def __init__(self, msg="Processando"):
        self.msg, self.running = msg, False
    def spin(self):
        spinner = itertools.cycle(['|', '/', '-', '\\'])
        while self.running:
            sys.stdout.write(f'\r{Fore.CYAN}{self.msg} {next(spinner)}{Style.RESET_ALL}')
            sys.stdout.flush()
            time.sleep(0.1)
    def __enter__(self):
        self.running = True
        threading.Thread(target=self.spin).start()
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.running = False
        sys.stdout.write('\r' + ' ' * (len(self.msg) + 10) + '\r')
        sys.stdout.flush()

# --- FERRAMENTAS TÉCNICAS (NOVAS IMPLEMENTAÇÕES) ---

def extrair_url(texto):
    url_pattern = re.compile(r'(?:http[s]?://)?(?:www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?')
    urls = url_pattern.findall(texto)
    valid_urls = [u for u in urls if "." in u] 
    return valid_urls[0] if valid_urls else None

def limpar_dominio(url):
    domain = url.split("://")[-1].split("/")[0].split(":")[0]
    if domain.startswith("www."): domain = domain[4:]
    return domain.lower()

# 1. Análise de Redirecionamento e Scraping
def analisar_conteudo_site(url):
    """Segue redirecionamentos e pega o texto da página."""
    if not url.startswith("http"): url = "http://" + url
    try:
        # User-Agent para não ser bloqueado como bot simples
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0'}
        # allow_redirects=True é padrão, mas explicitando
        response = requests.get(url, headers=headers, timeout=4, allow_redirects=True)
        
        url_final = response.url
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Limpa scripts e estilos
        for script in soup(["script", "style"]): script.extract()
        
        titulo = soup.title.string if soup.title else "Sem título"
        texto = soup.get_text(separator=' ', strip=True)[:1000] # Limita a 1000 chars
        
        return {
            "status": "Sucesso",
            "url_final": url_final,
            "foi_redirecionado": url != url_final,
            "titulo": titulo,
            "conteudo_resumo": texto
        }
    except Exception as e:
        return {"status": "Erro ao acessar", "detalhe": str(e)}

# 2. Verificação de SSL (Issuer)
def checar_ssl(url):
    """Verifica quem emitiu o certificado."""
    try:
        domain = limpar_dominio(url)
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])
                common_name = issuer.get('commonName', 'Desconhecido')
                org = issuer.get('organizationName', 'Não Informada')
                return f"Emitido por: {common_name} ({org})"
    except:
        return "Sem HTTPS ou Erro SSL"

# 3. Typosquatting (Visual)
def checar_typosquatting(url):
    """Compara o domínio com marcas famosas."""
    domain = limpar_dominio(url)
    alertas = []
    
    for alvo in ALVOS_TYPOSQUATTING:
        # Se for igual ao alvo, é seguro (é o próprio site)
        if domain == alvo or domain.endswith("." + alvo):
            continue
            
        # Calcula similaridade (0 a 1)
        ratio = difflib.SequenceMatcher(None, domain, alvo).ratio()
        
        # Se for muito parecido (> 0.75) mas não é igual -> Golpe visual
        if ratio > 0.75:
            alertas.append(f"Parece muito com '{alvo}' (Possível Golpe Visual)")
            
    return alertas if alertas else "Nenhuma imitação detectada"

# Ferramentas Antigas (Mantidas)
def checar_google_safebrowsing(url):
    if not GOOGLE_SB_KEY: return "N/A"
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_KEY}"
        payload = {"client": {"clientId": "gb", "clientVersion": "1"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
        res = requests.post(api_url, json=payload).json()
        return "PERIGOSO (Google)" if "matches" in res and res["matches"] else "Limpo"
    except: return "Erro"

def checar_virustotal(url):
    if not VIRUSTOTAL_KEY: return "N/A"
    try:
        uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers={"x-apikey": VIRUSTOTAL_KEY})
        if res.status_code == 200:
            st = res.json()['data']['attributes']['last_analysis_stats']
            return f"Malicious: {st.get('malicious',0)}"
        return "URL Nova/Desc."
    except: return "Erro"

def checar_idade_dominio(url):
    try:
        d = whois.whois(limpar_dominio(url))
        if d.text and ("No match" in d.text or "not found" in d.text.lower()): return "INEXISTENTE"
        date = d.creation_date
        if isinstance(date, list): date = date[0]
        if not date: return "Desc."
        if date.tzinfo: date = date.replace(tzinfo=None)
        return f"{(datetime.now() - date).days} dias"
    except: return "Erro Whois"

# --- CÉREBRO DA IA (Prompt V11) ---

def analisar_com_ia(url, dados_completos):
    if not MODELO_IA: return f"{Fore.RED}Erro IA{Style.RESET_ALL}"

    prompt = f"""
    Atue como 'GuardianBot', um consultor de segurança digital profissional.
    Analise os dados técnicos avançados abaixo e dê um veredicto para um usuário leigo (mas trate-o como adulto).

    --- DADOS TÉCNICOS ---
    URL Original: {url}
    URL Final (Redirecionamento): {dados_completos['conteudo'].get('url_final')}
    Título do Site: {dados_completos['conteudo'].get('titulo')}
    Resumo do Texto do Site: {dados_completos['conteudo'].get('conteudo_resumo')}
    
    Typosquatting (Imitação): {dados_completos['typosquatting']}
    Emissor SSL: {dados_completos['ssl']}
    Idade do Site: {dados_completos['idade']}
    Blacklist Local: {dados_completos['blacklist']}
    Google Safe Browsing: {dados_completos['google']}
    VirusTotal: {dados_completos['vt']}
    ----------------------

    --- REGRAS DE OURO ---
    1. **SSL:** Se o site for de Banco/Governo/Loja Grande mas o SSL for "Let's Encrypt" ou "cPanel", é 99% GOLPE.
    2. **Conteúdo:** Se o texto tiver "Sua senha expirou", "Bloqueio judicial", "Resgate Pix" em site não oficial, é GOLPE.
    3. **Typosquatting:** Se detectou imitação visual (ex: 'nubamk'), é GOLPE.
    4. **Idade:** Site < 30 dias pedindo dados? GOLPE.

    --- FORMATO DE RESPOSTA ---
    [EMOJI: 🛑, ⚠️ ou ✅] [VEREDICTO]
    ------------------------------
    [Explicação técnica traduzida para linguagem simples. Cite evidências como "O site imita o banco X" ou "O certificado de segurança é gratuito, o que bancos não usam".]
    
    [Ação Recomendada]
    """

    try:
        resp = MODELO_IA.generate_content(prompt)
        # Salva no dataset para treino futuro
        salvar_no_dataset(dados_completos, resp.text)
        return resp.text
    except Exception as e: return f"Erro IA: {e}"

# --- LOOP PRINCIPAL ---

def main():
    os.system('cls' if os.name == 'nt' else 'clear') 
    print(f"{Fore.CYAN}=== VERIFICADOR DE FRAUDE ==={Style.RESET_ALL}")
    
    if not MODELO_IA: print(f"{Fore.YELLOW}⚠️  IA Offline.{Style.RESET_ALL}")
    
    print("\nCole o link (ou 'sair'):")

    while True:
        try:
            msg = input(f"\n{Fore.BLUE}>> {Style.RESET_ALL}")
            if msg.strip().lower() in ['sair', 'fim']: break
            if not msg.strip(): continue

            url = extrair_url(msg)
            if not url:
                print("Link inválido.")
                continue
            
            # Dicionário para guardar tudo
            dados = {}
            
            with Spinner("🔍 Executando varredura completa..."):
                # Paralelismo aqui seria ideal, mas sequencial é mais seguro para evitar rate limits
                dados['google'] = checar_google_safebrowsing(url)
                dados['vt'] = checar_virustotal(url)
                dados['idade'] = checar_idade_dominio(url)
                dados['ssl'] = checar_ssl(url)
                dados['typosquatting'] = checar_typosquatting(url)
                dados['conteudo'] = analisar_conteudo_site(url)
                
                domain = limpar_dominio(url)
                dados['blacklist'] = "Sim" if domain in BLACKLIST_DOMAINS else "Não"

            with Spinner("🧠 IA Analisando evidências..."):
                analise = analisar_com_ia(url, dados)

            print(f"\n{Fore.GREEN}Resultado:{Style.RESET_ALL}\n{analise}\n{'-'*40}")
            print(f"{Style.DIM}(Dados salvos em dataset_treino.json){Style.RESET_ALL}")
            
        except KeyboardInterrupt: break
        except Exception as e: print(f"Erro: {e}")

if __name__ == "__main__":
    main()