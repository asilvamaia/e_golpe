import streamlit as st
import streamlit.components.v1 as components 
import time
import pandas as pd
import json
import os
import re
from datetime import datetime
import asyncio
from core import (
    extrair_url, 
    validar_seguranca_url, 
    limpar_dominio, 
    carregar_listas_seguranca,
    orquestrar_coleta_dados_url,
    analisar_com_ia,        
    analisar_texto_ia,
    checar_cache_analise,
    salvar_feedback,
    desencurtar_link,
    registrar_log,
    LOG_FILE
)
from database.db import SessionLocal
from database.models import DatasetItem, Feedback, DomainList

ICON_URL = "https://img.icons8.com/?size=100&id=Q7x2cp7xuVAG&format=png&color=000000"

st.set_page_config(
    page_title="É Golpe?",
    page_icon=ICON_URL,
    layout="centered",
    initial_sidebar_state="collapsed"
)

# --- ESTILIZAÇÃO IOS ---
def configurar_visual_ios():
    st.markdown("""
        <style>
        :root { --ios-bg: #F2F2F7; --ios-card: #FFFFFF; --ios-text: #000000; --ios-button: #007AFF; }
        @media (prefers-color-scheme: dark) { :root { --ios-bg: #000000; --ios-card: #1C1C1E; --ios-text: #FFFFFF; --ios-button: #0A84FF; } }
        .stApp { background-color: var(--ios-bg); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
        
        /* Layout Limpo */
        #MainMenu, footer, header {visibility: hidden;}
        .block-container { padding-top: 2rem; padding-bottom: 5rem; }
        
        /* Inputs */
        div[data-baseweb="input"] { background-color: var(--ios-card) !important; border-radius: 12px; border: 1px solid rgba(0,0,0,0.1); }
        
        /* Botões */
        div.stButton > button[kind="primary"] { background-color: var(--ios-button) !important; color: white !important; border-radius: 12px; height: 50px; font-weight: 600; font-size: 16px; border: none; width: 100%; }
        div.stButton > button[kind="secondary"] { background-color: transparent !important; border: 1px solid #ddd !important; color: #333 !important; border-radius: 12px; height: 45px; }
        @media (prefers-color-scheme: dark) { div.stButton > button[kind="secondary"] { color: white !important; border-color: #444 !important; } }
        
        /* Componentes Customizados */
        .status-card { background-color: var(--ios-card); padding: 15px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); margin-bottom: 15px; text-align: center; border: 1px solid rgba(0,0,0,0.1); color: var(--ios-text); }
        .result-box { padding: 25px; border-radius: 16px; text-align: left; margin-bottom: 20px; box-shadow: 0 4px 15px rgba(0,0,0,0.08); border: 1px solid rgba(0,0,0,0.05); background-color: var(--ios-card); color: var(--ios-text); }
        .context-box { background-color: rgba(0,0,0,0.03); padding: 10px; border-radius: 8px; margin-bottom: 15px; text-align: center; font-size: 0.9em; color: #666; border: 1px dashed #ccc; }
        .verdict-header { text-align: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid #eee; }
        .verdict-title { font-size: 1.8rem; font-weight: 800; letter-spacing: -0.5px; }
        .risk-score { font-size: 1.1rem; color: #666; font-weight: 500; }
        
        /* Cores de Risco */
        .text-safe { color: #28a745; } .text-warning { color: #ffc107; } .text-danger { color: #dc3545; }
        
        /* Esconde Instruções Padrão */
        [data-testid="InputInstructions"] { display: none !important; }
        div[data-testid="InputInstructions"] { display: none !important; }
        </style>
    """, unsafe_allow_html=True)

configurar_visual_ios()

# --- FUNÇÕES DE UTILS E SEGURANÇA ---
def parse_ia(txt):
    """Extrai veredito e score do texto Markdown gerado pelo Core"""
    ver = re.search(r'\*\*Veredito:?\*\*\s*(\[?.*?\]?)', txt, re.I)
    if ver:
        raw_ver = ver.group(1).replace('[','').replace(']','').strip().upper()
        raw_ver = re.sub(r':\w+', '', raw_ver)
    else:
        raw_ver = "ANÁLISE"
        
    score_match = re.search(r'(?:Score|Nível de Segurança).*?(\d{1,3})', txt, re.I)
    score_val = score_match.group(1) if score_match else "??"
    
    if "SEGURO" in raw_ver or "CONFIÁVEL" in raw_ver: css="text-safe"; i="✅"
    elif "PERIGO" in raw_ver or "GOLPE" in raw_ver or "FAKE" in raw_ver or "ALERTA" in raw_ver or "OFFLINE" in raw_ver: css="text-danger"; i="🚫"
    else: css="text-warning"; i="⚠️"
    
    return raw_ver, score_val, css, i

def check_rate_limit(seconds=3):
    now = time.time()
    last = st.session_state.get('ultima_requisicao', 0)
    if now - last < seconds:
        return False, f"⏳ Aguarde {int(seconds - (now - last))}s..."
    st.session_state['ultima_requisicao'] = now
    return True, ""

def validar_seguranca_input(texto):
    t = texto.lower()
    block = ["ignore previous", "system prompt", "you are a", "act as", "mode developer", "desconsidere as instruções"]
    for b in block: 
        if b in t: return False, "Comando inválido detectado."
    if len(texto) > 4000: return False, "Texto muito longo."
    return True, ""

# --- DIALOGS (POPUPS) ---

@st.dialog("📲 Instalar Aplicativo")
def mostrar_instrucoes_instalacao():
    st.markdown("""
    <div style="text-align: left; font-size: 16px;">
        <p>Adicione à tela inicial para acesso rápido:</p>
        <hr><strong>🍎 iOS:</strong> Compartilhar ⬆️ > <b>"Adicionar à Tela de Início"</b>.
        <hr><strong>🤖 Android:</strong> Menu (⋮) > <b>"Adicionar à tela inicial"</b>.
    </div>""", unsafe_allow_html=True)

@st.dialog("⚖️ Termos de Uso")
def mostrar_disclaimer():
    # USANDO MARKDOWN NATIVO PARA EVITAR QUEBRA DE HTML
    st.markdown("""
    **1. Natureza Informativa**
    
    Este sistema ("GuardianBot") é uma ferramenta de consulta auxiliar baseada em Inteligência Artificial e bancos de dados públicos de segurança cibernética.

    **2. Limitações da Tecnologia**
    
    A detecção de ameaças não é infalível. Podem ocorrer:
    * **Falsos Positivos:** Sites seguros marcados como perigosos.
    * **Falsos Negativos:** Golpes novos (Zero-Day) ainda não catalogados.

    **3. Isenção de Responsabilidade**
    
    Os desenvolvedores e mantenedores deste serviço **não se responsabilizam** por quaisquer danos diretos, indiretos, financeiros, perda de dados ou roubo de identidade resultantes do acesso a links analisados por esta ferramenta.

    **4. Decisão Final**
    
    O acesso a qualquer site é de sua **exclusiva responsabilidade**. Utilize esta ferramenta como uma segunda opinião, mas sempre verifique os canais oficiais.
    """)
    st.markdown("---")
    if st.button("OK, Entendi", use_container_width=True):
        st.rerun()

# --- SESSION STATE ---
if 'texto_para_analisar' not in st.session_state: st.session_state['texto_para_analisar'] = ""
if 'ultima_requisicao' not in st.session_state: st.session_state['ultima_requisicao'] = 0
if 'ultimo_resultado_ia' not in st.session_state: st.session_state['ultimo_resultado_ia'] = None
if 'dados_tecnicos_cache' not in st.session_state: st.session_state['dados_tecnicos_cache'] = None
if 'feedback_enviado' not in st.session_state: st.session_state['feedback_enviado'] = False
if 'modo_admin' not in st.session_state: st.session_state['modo_admin'] = False
if 'admin_autenticado' not in st.session_state: st.session_state['admin_autenticado'] = False
if 'processing' not in st.session_state: st.session_state['processing'] = False

# --- LÓGICA DE LOGIN ADMIN ---
MAGIC_WORD = os.getenv("MAGIC_WORD", "Ck90t&c@@") # Fallback se não setado
ADMIN_PASS_HASH = os.getenv("ADMIN_PASS_HASH")

# Usando bcrypt para validar senha, caso configurada
import bcrypt
def verificar_senha(senha_raw, senha_hash):
    if not senha_hash: return False
    try:
        return bcrypt.checkpw(senha_raw.encode('utf-8'), senha_hash.encode('utf-8'))
    except:
        return False


def submeter_consulta():
    nova_entrada = st.session_state.widget_input
    
    if nova_entrada.strip() == MAGIC_WORD:
        st.session_state['modo_admin'] = True
        st.session_state.widget_input = ""
        return

    safe, msg_erro = validar_seguranca_input(nova_entrada)
    if not safe:
        st.toast(msg_erro, icon="❌")
        return

    ok, msg_rate = check_rate_limit()
    if not ok:
        st.toast(msg_rate, icon="⏳")
        return
    
    st.session_state['feedback_enviado'] = False
    st.session_state['ultimo_resultado_ia'] = None
    st.session_state['dados_tecnicos_cache'] = None
    st.session_state['texto_para_analisar'] = nova_entrada
    st.session_state.widget_input = ""
    st.session_state['processing'] = True

def realizar_login_admin():
    senha_digitada = st.session_state.senha_admin
    admin_hash_limpo = ADMIN_PASS_HASH.strip() if ADMIN_PASS_HASH else None
    
    # Se ADMIN_PASS_HASH não existir no .env ou for vazio, usa o fallback seguro
    fallback = os.getenv("ADMIN_PASS_FALLBACK")
    fallback = fallback.strip() if fallback else ""

    if admin_hash_limpo and verificar_senha(senha_digitada, admin_hash_limpo):
        st.session_state['admin_autenticado'] = True
    elif not admin_hash_limpo and senha_digitada == fallback:
        # FALLBACK temporário para não quebrar o app se o bcrypt não estiver configurado
        st.session_state['admin_autenticado'] = True
    else:
        st.error("Senha incorreta.")

def sair_admin():
    st.session_state['modo_admin'] = False
    st.session_state['admin_autenticado'] = False

def carregar_arquivo_lista(list_type):
    db = SessionLocal()
    try:
        records = db.query(DomainList.domain).filter(DomainList.list_type == list_type).all()
        return "\n".join([r[0] for r in records])
    finally:
        db.close()

def salvar_arquivo_lista(list_type, conteudo):
    db = SessionLocal()
    try:
        domains = [d.strip().lower() for d in conteudo.split("\n") if d.strip()]
        db.query(DomainList).filter(DomainList.list_type == list_type).delete()
        
        batch = [{"domain": d, "list_type": list_type} for d in set(domains)]
        if batch:
            db.bulk_insert_mappings(DomainList, batch)
        db.commit()
        st.toast(f"Lista {list_type} salva com sucesso!", icon="✅")
    except Exception as e:
        db.rollback()
        st.error(f"Erro ao salvar: {e}")
    finally:
        db.close()

def processar_feedback_wrapper(tipo):
    if st.session_state['texto_para_analisar'] and st.session_state['ultimo_resultado_ia']:
        salvar_feedback(st.session_state['texto_para_analisar'], st.session_state['ultimo_resultado_ia'], tipo)
        st.session_state['feedback_enviado'] = True
        st.toast("Obrigado pelo feedback!", icon="🙏")

def get_remote_ip():
    try:
        if hasattr(st, "context") and hasattr(st.context, "headers"):
            headers = st.context.headers
            return headers.get("X-Forwarded-For", "127.0.0.1").split(',')[0]
        return "127.0.0.1"
    except: return "127.0.0.1"

# --- INJEÇÃO DE JS ---
components.html(f"""<script>
    function injectAppleIcon() {{ var head = window.parent.document.getElementsByTagName('head')[0]; var link = window.parent.document.querySelector("link[rel='apple-touch-icon']"); if (!link) {{ link = window.parent.document.createElement('link'); link.rel = 'apple-touch-icon'; head.appendChild(link); }} link.href = '{ICON_URL}'; }}
    function manageInstallButton() {{ const isDesktop = window.parent.innerWidth > 768; const isStandalone = window.parent.matchMedia('(display-mode: standalone)').matches || window.parent.navigator.standalone === true; if (isDesktop || isStandalone) {{ const buttons = window.parent.document.getElementsByTagName('button'); for (let btn of buttons) {{ if (btn.innerText.includes('Instalar App')) {{ btn.style.display = 'none'; if (btn.parentElement && btn.parentElement.classList.contains('stButton')) {{ btn.parentElement.style.display = 'none'; }} }} }} }} }}
    injectAppleIcon(); setInterval(manageInstallButton, 1000);
    </script>""", height=0)

# --- INTERFACE PRINCIPAL ---

if st.session_state['modo_admin']:
    if not st.session_state['admin_autenticado']:
        st.title("🔒 Acesso Restrito")
        st.text_input("Senha de Administrador:", type="password", key="senha_admin", on_change=realizar_login_admin)
        if st.button("Voltar"): sair_admin()
    else:
        st.title("⚙️ Painel de Controle")
        if st.button("Sair"): sair_admin()
        
        tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["📊 Dashboard", "🕵️ Histórico", "✅ Whitelist", "🚫 Blacklist", "📜 Logs", "💾 Backups"])
        
        with tab1:
            st.subheader("Analytics")
            db = SessionLocal()
            try:
                # Analytics Dataset
                df = pd.read_sql(db.query(DatasetItem).statement, db.bind)
                if not df.empty:
                    df['data'] = pd.to_datetime(df['timestamp']).dt.date
                    col1, col2 = st.columns(2)
                    col1.metric("Consultas Totais", len(df))
                    st.bar_chart(df.groupby('data').size())
                else: 
                    st.info("Sem dados de consultas.")

                # Analytics Feedbacks
                df_f = pd.read_sql(db.query(Feedback).statement, db.bind)
                if not df_f.empty:
                    st.subheader("Feedbacks")
                    st.bar_chart(df_f['avaliacao'].value_counts())
            except Exception as e:
                st.error(f"Erro no Analytics: {e}")
            finally:
                db.close()

        with tab2:
            st.subheader("Histórico de Consultas")
            db = SessionLocal()
            try:
                query = db.query(DatasetItem).order_by(DatasetItem.timestamp.desc()).limit(100).all()
                if query:
                    table_data = []
                    for item in query:
                        meta = item.metadados or {}
                        origem = meta.get('origem', meta.get('ip', 'Desconhecido'))
                        dados_tec = item.dados_tecnicos or {}
                        entrada = dados_tec.get('input') or dados_tec.get('url_final') or dados_tec.get('texto_puro') or "N/A"
                        raw_veredito = item.analise_modelo or ""
                        
                        veredito_limpo = "Indefinido"
                        if "SEGURO" in raw_veredito: veredito_limpo = "✅ SEGURO"
                        elif "PERIGO" in raw_veredito or "GOLPE" in raw_veredito: veredito_limpo = "🚨 GOLPE"
                        elif "ALERTA" in raw_veredito: veredito_limpo = "⚠️ ALERTA"
                        
                        table_data.append({
                            "Data": pd.to_datetime(item.timestamp).strftime('%d/%m %H:%M'),
                            "Origem": origem,
                            "Consulta": str(entrada)[:60],
                            "Status": veredito_limpo
                        })
                    
                    df_hist = pd.DataFrame(table_data)
                    st.dataframe(df_hist, width=1000, hide_index=True)
                else:
                    st.info("Nenhum histórico disponível.")
            except Exception as e:
                st.error(f"Erro histórico: {e}")
            finally:
                db.close()

        with tab3:
            st.subheader("Whitelist")
            cw = carregar_arquivo_lista("whitelist")
            nw = st.text_area("Domínios Seguros", value=cw, height=300)
            if st.button("Salvar WL"): salvar_arquivo_lista("whitelist", nw)

        with tab4:
            st.subheader("Blacklist")
            cb = carregar_arquivo_lista("blacklist")
            nb = st.text_area("Domínios Bloqueados", value=cb, height=300)
            if st.button("Salvar BL"): salvar_arquivo_lista("blacklist", nb)

        with tab5:
            st.subheader("Logs")
            if LOG_FILE.exists():
                with open(LOG_FILE, 'r') as f: st.code("".join(f.readlines()[-50:]))
            else: st.info("Vazio.")

        with tab6:
            st.subheader("Bkp do Banco de Dados")
            st.write("Baixe todas as tabelas do PostgreSQL para segurança.")
            if st.button("Gerar Arquivo de Backup (.ZIP)"):
                import io
                import zipfile
                db = SessionLocal()
                try:
                    with st.spinner("Extraindo banco de dados..."):
                        zip_buffer = io.BytesIO()
                        with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
                            # Tabela Analises (Dataset)
                            df_hist = pd.read_sql(db.query(DatasetItem).statement, db.bind)
                            zip_file.writestr("historico_analises.csv", df_hist.to_csv(index=False))
                            
                            # Tabela Feedbacks
                            df_feed = pd.read_sql(db.query(Feedback).statement, db.bind)
                            zip_file.writestr("feedbacks.csv", df_feed.to_csv(index=False))
                            
                            # Tabela Listas
                            df_list = pd.read_sql(db.query(DomainList).statement, db.bind)
                            zip_file.writestr("listas_brancas_negras.csv", df_list.to_csv(index=False))

                        st.success("Backup gerado com sucesso!")
                        st.download_button(
                            label="⬇️ Baixar Backup Agora",
                            data=zip_buffer.getvalue(),
                            file_name=f"egolpe_backup_{datetime.now().strftime('%Y%m%d_%H%M')}.zip",
                            mime="application/zip"
                        )
                except Exception as e:
                    st.error(f"Erro ao gerar backup: {e}")
                finally:
                    db.close()

else:
    st.markdown("<h1 style='text-align: center; margin-bottom: 0px;'>🛡️ É Golpe?</h1>", unsafe_allow_html=True)
    st.markdown("<h3 style='text-align: center; color: gray; margin-top: -10px; font-size: 1rem;'>IA contra Fraudes Digitais</h3>", unsafe_allow_html=True)

    with st.form(key='form_verificacao'):
        locked = st.session_state['processing']
        st.text_input("Link ou Mensagem:", placeholder="Cole aqui...", key="widget_input", disabled=locked)
        st.form_submit_button("Analisar Risco", type="primary", on_click=submeter_consulta, disabled=locked)

    texto_analise = st.session_state['texto_para_analisar']

    if texto_analise and st.session_state['processing']:
        url_check = extrair_url(texto_analise)
        status_box = st.empty()
        status_box.markdown(f"<div class='status-card'>🔎 Iniciando auditoria...</div>", unsafe_allow_html=True)
        
        user_ip = get_remote_ip()
        meta_web = {"origem": f"Web ({user_ip})"}
        resultado_final = ""
        dados_tecnicos_capturados = None

        try:
            if url_check:
                status_box.markdown(f"<div class='status-card'>🌐 Auditando domínio...</div>", unsafe_allow_html=True)
                
                if not url_check.startswith("http"): url_temp = "http://" + url_check
                else: url_temp = url_check
                url_final, foi_desencurtado = desencurtar_link(url_temp)
                
                if foi_desencurtado:
                    st.toast(f"Redirecionamento: {limpar_dominio(url_final)}", icon="➡️")

                domain_clean = limpar_dominio(url_final)
                
                # Check de Blacklist
                _, blacklist = carregar_listas_seguranca()
                eh_blacklist = False
                for bad in blacklist:
                    if bad in domain_clean: eh_blacklist = True; break
                
                if eh_blacklist:
                    status_box.empty()
                    resultado_final = f"""
                    **Veredito:** :red[**GOLPE**]

                    🛡️ **Nível de Segurança:** 0/100

                    **Análise:**
                    Este domínio ({domain_clean}) foi identificado no banco de dados de ameaças ativas.
                    
                    **Ação:**
                    - 🚫 NÃO ACESSE este site.
                    - Bloqueie o remetente.
                    """
                else:
                    seguro_tecnico, motivo, url_validada = validar_seguranca_url(url_final)
                    
                    if not seguro_tecnico and "DNS_FAIL" in motivo:
                        status_box.empty()
                        resultado_final = f"""
                        **Veredito:** :orange[**SITE OFFLINE**]

                        🛡️ **Nível de Segurança:** 0/100

                        **Análise:**
                        Não conseguimos conectar ao site **{domain_clean}**.
                        
                        **Por que isso acontece?**
                        1. O site pode ter sido **derrubado por denúncias de fraude**.
                        2. O endereço pode não existir.
                        3. O servidor está desligado.

                        **Ação Recomendada:**
                        ⚠️ **Tenha cautela redobrada.** Se você recebeu este link com promessas de ganhos ou cobranças urgentes, é muito provável que seja um golpe que já foi neutralizado.
                        """
                    
                    elif not seguro_tecnico:
                        status_box.empty()
                        st.error(f"🚫 **Bloqueio de Segurança:** {motivo}")
                        resultado_final = None
                    
                    else:
                        status_box.markdown(f"<div class='status-card'>🤖 IA verificando padrões...</div>", unsafe_allow_html=True)
                        url_final = url_validada
                        domain_clean = limpar_dominio(url_final)
                        
                        whitelist, _ = carregar_listas_seguranca()
                        eh_confiavel = False
                        for safe in whitelist:
                            if domain_clean == safe or domain_clean.endswith("." + safe): eh_confiavel = True; break
                        
                        if eh_confiavel:
                            resultado_final = f"**Veredito:** :green[**SEGURO**]\n\n**Score:** 100/100\n\n✅ **SITE OFICIAL:** {domain_clean}\nEste é um domínio verificado."
                        else:
                            cache_analise, cache_dados = checar_cache_analise(url_final)
                            if cache_analise:
                                dados_tecnicos_capturados = cache_dados
                                resultado_final = cache_analise + "\n\n*(⚡ Resultado obtido do Cache)*"
                            else:
                                dados = asyncio.run(orquestrar_coleta_dados_url(url_final))
                                dados_tecnicos_capturados = dados 
                                resultado_final = asyncio.run(analisar_com_ia(url_final, dados, origem="streamlit", metadados=meta_web))
            else:
                status_box.markdown(f"<div class='status-card'>🧠 IA lendo mensagem...</div>", unsafe_allow_html=True)
                cache_analise, _ = checar_cache_analise(texto_analise)
                if cache_analise:
                    resultado_final = cache_analise + "\n\n*(⚡ Resultado obtido do Cache)*"
                else:
                    resultado_final = asyncio.run(analisar_texto_ia(texto_analise, origem="streamlit", metadados=meta_web))

            status_box.empty() 
            
            if resultado_final:
                st.session_state['ultimo_resultado_ia'] = resultado_final
                st.session_state['dados_tecnicos_cache'] = dados_tecnicos_capturados
            
        except Exception as e:
            status_box.empty()
            st.error(f"Erro interno: {e}")
            registrar_log(f"Erro Frontend: {e}", "ERRO")
        
        st.session_state['processing'] = False
        st.rerun()

    if st.session_state['ultimo_resultado_ia']:
        txt_orig = st.session_state['texto_para_analisar']
        resumo = txt_orig[:60] + "..." if len(txt_orig) > 60 else txt_orig
        st.markdown(f"<div class='context-box'>Analisando: <b>{resumo}</b></div>", unsafe_allow_html=True)

        txt_ia = st.session_state['ultimo_resultado_ia']
        
        ver, score, css, icon = parse_ia(txt_ia)
        
        clean_txt = re.sub(r'.*Veredito:?.*\n?', '', txt_ia, flags=re.I)
        clean_txt = re.sub(r'.*(?:Score|Nível de Segurança).*\n?', '', clean_txt, flags=re.I)
        clean_txt = clean_txt.split("⚠️ REGRA VISUAL")[0].strip()

        st.markdown(f"""
        <div class="result-box">
            <div class="verdict-header">
                <div class="verdict-title {css}">{icon} {ver}</div>
                <div class="risk-score">Nível de Segurança: <b>{score}/100</b></div>
            </div>
            <div style="font-size: 16px; line-height: 1.6; color: var(--ios-text);">{clean_txt.replace(chr(10), '<br>')}</div>
        </div>""", unsafe_allow_html=True)

        if st.session_state.get('dados_tecnicos_cache'):
            d = st.session_state['dados_tecnicos_cache']
            with st.expander("📊 Detalhes Técnicos", expanded=False):
                c1, c2 = st.columns(2)
                c1.metric("Idade", d.get("idade", "?"))
                ssl_info = d.get("ssl", "")
                c2.metric("SSL", "Válido" if "Emitido" in ssl_info else "Risco")
                
                scan_res = d.get('urlscan', '')
                if "MALICIOSO" in scan_res: st.error(f"URLScan: {scan_res}")
                
                typo = d.get("typosquatting")
                if typo != "Não": st.error(f"Clone de Marca: {typo}")

        if not st.session_state['feedback_enviado']:
            st.markdown("---")
            c1, c2 = st.columns(2)
            with c1: st.button("👍 Útil", use_container_width=True, on_click=processar_feedback_wrapper, args=("POSITIVO",), type="secondary")
            with c2: st.button("👎 Errado", use_container_width=True, on_click=processar_feedback_wrapper, args=("NEGATIVO",), type="secondary")
        else:
            st.caption("Feedback enviado. Obrigado!")

    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("📲 Instalar App", type="secondary", use_container_width=True):
        mostrar_instrucoes_instalacao()
    
    if st.button("📜 Termos de Uso", type="secondary", use_container_width=True):
        mostrar_disclaimer()

    st.caption("Beta - Ajude a manter o serviço ativo: https://livepix.gg/asmaia")