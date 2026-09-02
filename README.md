# 🛡️ É Golpe? — Sistema Integrado de Detecção de Fraudes e Golpes Digitais

Sistema inteligente multiplataforma para proteção contra fraudes, golpes virtuais, fake news e vazamentos de dados, desenvolvido com foco especial em usabilidade e acessibilidade para usuários leigos e idosos.

---

## 📱 Componentes do Ecossistema

1. **Aplicativo Mobile (Flutter - Android & iOS / AltStore)**:
   - Suporte a verificação de **Links/Sites**, **Mensagens de Texto (SMS/WhatsApp)** e **Fotos/Prints/PDFs (OCR)**.
   - Verificador de senhas vazadas em bases globais (**Have I Been Pwned** via k-anonymity).
   - **Narração por voz integrada (TTS)** e **Modo Alto Contraste para Idosos**.
   - Guia educacional com os principais golpes no Brasil e botões de emergência (190, 100, 181).
   - Histórico local de escaneamentos e compartilhamento rápido de alertas.
   - Compilação automatizada via **GitHub Actions** (`.apk` para Android e `.ipa` sideloadable para AltStore no iOS).

2. **Backend API (FastAPI)**:
   - Rotas assíncronas de alta performance (`/api/v1/analyze`, `/api/v1/analyze-text`, `/api/v1/analyze-file`, `/api/v1/check-password`, `/api/v1/feedback`, `/api/v1/stats`).
   - Autenticação por chave de API (`x-api-key`) e CORS configurado.
   - Cache em camadas (Redis + SQLite/Postgres).

3. **Painel Web (Streamlit)**:
   - Interface web amigável com geração de relatórios, gráficos e estatísticas.

4. **Bot do Telegram**:
   - Atendimento automático 24/7 para verificação rápida de mensagens, links e fotos enviadas no chat.

5. **Extensão de Navegador (Chrome / Edge)**:
   - Auditoria com 1 clique da página atual em navegação.

---

## 🚀 Como Compilar o App Mobile via GitHub Actions

O repositório já conta com o fluxo de integração contínua configurado em [`.github/workflows/build_mobile.yml`](.github/workflows/build_mobile.yml).

### 1. Compilação Automática
- Sempre que você fizer um `git push` na branch `main` ou criar uma tag de versão (`v1.0.0`), o GitHub Actions compilará automaticamente:
  - **Android**: `egolpe-android-release.apk` (para instalar diretamente no Android) e `egolpe-android-release.aab` (Google Play).
  - **iOS**: `egolpe-ios-altstore.ipa` (empacotado especialmente para instalação via AltStore).

### 2. Baixar os Arquivos Compilados
1. No seu repositório do GitHub, clique na aba **Actions**.
2. Selecione a execução mais recente do workflow **Build Mobile Apps**.
3. Na seção **Artifacts**, baixe:
   - `egolpe-android-apk`
   - `egolpe-ios-altstore-ipa`

---

## 📲 Como Instalar no iPhone via AltStore

1. Baixe o arquivo `egolpe-ios-altstore.ipa` no seu iPhone (ou transfira via iCloud/AirDrop).
2. Abra o aplicativo **AltStore** no iPhone.
3. Acesse a aba **My Apps** e toque no botão **+** (canto superior esquerdo).
4. Selecione o arquivo `egolpe-ios-altstore.ipa`.
5. O AltStore assinará o aplicativo com seu Apple ID e o instalará no dispositivo!

---

## ⚙️ Variáveis de Ambiente (`.env`)

Crie um arquivo `.env` na raiz do projeto com as chaves desejadas:

```env
# Google Gemini AI (Obrigatório para o cérebro de IA)
GOOGLE_AI_KEY=sua_chave_gemini_aqui
GEMINI_MODEL=gemini-2.0-flash

# Chaves de Segurança Externa (Opcionais para enriquecimento)
VIRUSTOTAL_API_KEY=sua_chave_virustotal
URLSCAN_API_KEY=sua_chave_urlscan
GOOGLE_API_KEY=sua_chave_google_search
GOOGLE_SEARCH_CX=seu_cx_custom_search

# Bot do Telegram (Opcional)
TELEGRAM_BOT_TOKEN=seu_token_bot_telegram

# Chave de Segurança da API (Opcional - se vazio, a API opera aberta)
API_KEY_SECRET=sua_chave_secreta_aqui
REQUIRE_API_KEY=true
CORS_ALLOWED_ORIGINS=https://fraude.servicos.ia.br,https://servicos.ia.br
CORS_ALLOWED_ORIGIN_REGEX=^(chrome-extension|moz-extension)://.+$

# Banco de Dados e Cache
DATABASE_URL=sqlite:///guardian.db
REDIS_URL=redis://127.0.0.1:6379
```

---

## 🐳 Executando com Docker

Para iniciar todos os serviços unificados (FastAPI + Streamlit + Bot Telegram + Nginx):

```bash
docker build -t ia-contra-fraude .
docker run -p 8080:8080 --env-file .env ia-contra-fraude
```

Acesse:
- **Painel Web**: http://localhost:8080/
- **Documentação da API (Swagger)**: http://localhost:8080/docs
- **Health Check**: http://localhost:8080/health
