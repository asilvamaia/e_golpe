# 🛡️ É Golpe?

**É Golpe?** é uma plataforma de apoio à prevenção de fraudes e golpes digitais. O projeto analisa links, mensagens, imagens e documentos suspeitos, reúne sinais técnicos com inteligência artificial e apresenta um resultado simples, com pontuação de segurança e orientações práticas.

A interface foi pensada para pessoas com diferentes níveis de familiaridade com tecnologia, com atenção especial à legibilidade, contraste, responsividade e facilidade de uso.

> **Aviso:** o resultado é uma análise automatizada de apoio à decisão. Nenhuma ferramenta consegue garantir que um conteúdo seja totalmente seguro. Em caso de dúvida, não clique, não envie dinheiro ou dados pessoais e procure a instituição envolvida por seus canais oficiais.

## Acesso

- Site: [fraude.servicos.ia.br](https://fraude.servicos.ia.br)
- API: [ia-contra-fraude.fly.dev](https://ia-contra-fraude.fly.dev)
- Documentação interativa da API: [ia-contra-fraude.fly.dev/docs](https://ia-contra-fraude.fly.dev/docs)

## Funcionalidades

- Análise de mensagens recebidas por SMS, WhatsApp, e-mail e outros canais
- Verificação de links, redirecionamentos e sinais técnicos do domínio
- Análise de imagens, capturas de tela e documentos PDF com OCR/IA
- Consulta de senhas expostas usando o modelo de privacidade k-anonymity
- Pontuação de segurança de 0 a 100 e classificação visual do risco
- Cache de análises para respostas mais rápidas
- Coleta de feedback para melhoria contínua
- Interface responsiva e acessível
- Integrações com aplicativo Flutter, bot do Telegram e extensão de navegador

## Arquitetura

| Componente | Tecnologia | Função |
| --- | --- | --- |
| Frontend web | Next.js 16, React 19 e TypeScript | Interface pública e proxy seguro para a API |
| API | FastAPI e Python | Validação, análise e integração entre serviços |
| Motor de análise | Python e Google Gemini | Combinação de regras, fontes externas e IA |
| Interface legada | Streamlit | Painel mantido no backend durante a transição |
| Persistência | SQLite ou PostgreSQL | Histórico, usuários, dataset e feedback |
| Cache | Redis, quando configurado | Reutilização de resultados |
| Infraestrutura | Vercel, Fly.io, Docker e Nginx | Hospedagem e proxy reverso |
| App | Flutter | Cliente para Android, iOS e outras plataformas |
| Extensão | Manifest V3 | Verificação da página aberta no navegador |
| Bot | Telegram | Análise de links, mensagens, imagens e PDFs pelo chat |

O navegador não recebe a chave privada da API. O frontend envia as solicitações para um Route Handler do Next.js, que acrescenta a credencial somente no servidor e encaminha a requisição ao FastAPI.

## Estrutura do repositório

```text
.
├── main.py                 # API FastAPI
├── core.py                 # Motor de coleta e análise
├── app.py                  # Interface Streamlit
├── database/               # Configuração e modelos do banco
├── web/                    # Frontend Next.js
├── mobile_app/             # Aplicativo Flutter
├── browser_extension/      # Extensão Chrome/Edge
├── telegram_bot.py         # Bot do Telegram
├── scripts/                # Migração e preparação de dados
├── Dockerfile
├── nginx.conf
├── start.sh
└── fly.toml
```

## Requisitos

Para executar o backend:

- Python 3.10 ou superior
- `whois` instalado no sistema
- Uma chave da API Google Gemini
- Redis e PostgreSQL são opcionais; sem `DATABASE_URL`, o projeto usa SQLite

Para executar o frontend:

- Node.js compatível com Next.js 16
- npm

## Configuração

Crie um arquivo `.env` na raiz:

```env
GOOGLE_AI_KEY=sua_chave_google_ai
GEMINI_MODEL=gemini-2.0-flash

API_KEY_SECRET=crie_um_segredo_forte
REQUIRE_API_KEY=true

CORS_ALLOWED_ORIGINS=http://localhost:3000,https://fraude.servicos.ia.br,https://servicos.ia.br
CORS_ALLOWED_ORIGIN_REGEX=^(chrome-extension|moz-extension)://.+$

DATABASE_URL=sqlite:///guardian.db
REDIS_URL=redis://127.0.0.1:6379

# Integrações opcionais
VIRUSTOTAL_API_KEY=
URLSCAN_API_KEY=
GOOGLE_API_KEY=
GOOGLE_SEARCH_CX=
TELEGRAM_BOT_TOKEN=
```

Não publique arquivos `.env`, tokens ou chaves no repositório.

### Frontend

Copie o arquivo de exemplo:

```bash
cd web
cp .env.example .env.local
```

Configure as variáveis:

```env
API_BASE_URL=http://127.0.0.1:8000
API_KEY_SECRET=o_mesmo_segredo_configurado_no_backend
```

`API_KEY_SECRET` é lida apenas no servidor pelo proxy do Next.js.

## Execução local

### Backend FastAPI

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

No Windows PowerShell, ative o ambiente com:

```powershell
.\.venv\Scripts\Activate.ps1
```

A API ficará disponível em `http://127.0.0.1:8000` e o Swagger em `http://127.0.0.1:8000/docs`.

### Frontend Next.js

Em outro terminal:

```bash
cd web
npm install
npm run dev
```

Acesse `http://localhost:3000`.

### Streamlit

Para executar somente a interface legada:

```bash
streamlit run app.py
```

## Docker

O contêiner inicia FastAPI, Streamlit, o bot do Telegram quando configurado e o Nginx na porta 8080:

```bash
docker build -t e-golpe .
docker run --rm -p 8080:8080 --env-file .env e-golpe
```

Acesse:

- Interface Streamlit: `http://localhost:8080/`
- API: `http://localhost:8080/api/v1/health`
- Swagger: `http://localhost:8080/docs`
- Health check: `http://localhost:8080/health`

## Principais endpoints

| Método | Endpoint | Descrição |
| --- | --- | --- |
| `GET` | `/health` | Estado do serviço |
| `POST` | `/api/v1/analyze` | Análise unificada de texto ou URL |
| `POST` | `/api/v1/analyze-text` | Análise de mensagem |
| `POST` | `/api/v1/analyze-file` | Análise de imagem ou PDF |
| `POST` | `/api/v1/check-password` | Consulta de senha exposta |
| `POST` | `/api/v1/feedback` | Registro de avaliação |
| `GET` | `/api/v1/stats` | Estatísticas do serviço |

Quando `REQUIRE_API_KEY=true`, envie a chave no cabeçalho:

```http
x-api-key: sua_chave
```

Exemplo:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -H "x-api-key: sua_chave" \
  -d '{"text":"https://exemplo.com","source":"api"}'
```

## Deploy

### Backend no Fly.io

O arquivo `fly.toml` usa a aplicação `ia-contra-fraude`, porta interna 8080 e volume persistente montado em `/data`.

```bash
fly secrets set GOOGLE_AI_KEY="..." API_KEY_SECRET="..." REQUIRE_API_KEY="true"
fly deploy
```

As demais variáveis sensíveis devem ser cadastradas como secrets, nunca gravadas no `fly.toml`.

### Frontend na Vercel

- Defina `web` como **Root Directory**
- Cadastre `API_BASE_URL` e `API_KEY_SECRET`
- Faça o deploy da branch `main`
- Aponte o domínio `fraude.servicos.ia.br` para o projeto

Na interface web, uploads são limitados a 4 MB pelo proxy serverless. A API aceita imagens PNG, JPG e WEBP ou PDF com até 20 MB quando acessada diretamente.

## Aplicativo mobile

O workflow [`.github/workflows/build_mobile.yml`](.github/workflows/build_mobile.yml) executa os testes e compila:

- APK universal para Android
- AAB para publicação na Google Play
- IPA sem assinatura para instalação via AltStore ou Sideloadly

Os artefatos ficam disponíveis por 30 dias na execução correspondente da aba **Actions**. Tags no formato `v*` também podem gerar uma GitHub Release.

## Privacidade e segurança

- A chave da API permanece no servidor
- A API pode exigir autenticação por `x-api-key`
- CORS deve ser limitado aos domínios usados pelo projeto
- URLs passam por validações antes da coleta
- A consulta de senha usa somente uma parte do hash; a senha completa não é enviada ao serviço externo
- Arquivos e dados suspeitos devem ser tratados como conteúdo sensível
- Logs, bancos, datasets e backups reais não devem ser incluídos em commits públicos

## Status

Projeto em desenvolvimento contínuo. A nova interface Next.js é a experiência web principal, enquanto a API FastAPI e os demais clientes compartilham o mesmo motor de análise.

---

Uma iniciativa **Serviços IA**.
