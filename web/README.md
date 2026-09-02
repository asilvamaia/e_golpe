# É Golpe? — nova interface web

Frontend Next.js para a API FastAPI existente. O Streamlit continua ativo durante a transição.

## Desenvolvimento

1. Copie `.env.example` para `.env.local`.
2. Defina `API_BASE_URL` e, se a API estiver protegida, `API_KEY_SECRET`.
3. Execute `npm install` e `npm run dev`.

O segredo é usado somente pelo Route Handler no servidor e nunca é enviado ao navegador.

## Vercel

Configure o diretório raiz do projeto como `web` e cadastre as duas variáveis de ambiente. O domínio público sugerido é `fraude.servicos.ia.br`.

Durante a primeira fase, uploads na nova interface são limitados a 4 MB pelo proxy serverless. O Streamlit permanece como fallback para arquivos de até 20 MB até a implementação do upload direto assinado.
