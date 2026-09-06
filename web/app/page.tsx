"use client";

import { ChangeEvent, FormEvent, useEffect, useRef, useState } from "react";

type Mode = "message" | "link" | "file" | "password";
type Analysis = {
  verdict?: string;
  score?: number;
  level?: string;
  icon?: string;
  analysis?: string;
  breached?: boolean;
  message?: string;
  cached?: boolean;
};

async function readApiResponse(response: Response): Promise<Analysis & { detail?: string }> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    throw new Error(
      response.status === 504
        ? "O serviço demorou mais que o esperado. Tente novamente em alguns instantes."
        : "O serviço retornou uma resposta inválida. Tente novamente.",
    );
  }

  try {
    return await response.json();
  } catch {
    throw new Error("Não foi possível interpretar a resposta do serviço. Tente novamente.");
  }
}

const modes = [
  { id: "message" as const, icon: "✉", label: "Mensagem", hint: "SMS, WhatsApp ou e-mail" },
  { id: "link" as const, icon: "↗", label: "Link", hint: "Site ou endereço suspeito" },
  { id: "file" as const, icon: "▤", label: "Imagem ou PDF", hint: "Print, boleto ou documento" },
  { id: "password" as const, icon: "●", label: "Senha", hint: "Consulte vazamentos conhecidos" },
];

const warningCards = [
  {
    icon: "PIX",
    title: "Falso Pix ou tarefa",
    text: "Promessas de dinheiro fácil podem terminar em cobranças para liberar um suposto saldo.",
    tip: "Nunca pague para receber um prêmio.",
  },
  {
    icon: "SMS",
    title: "Falsa entrega",
    text: "Mensagens sobre encomendas retidas costumam levar a páginas falsas de pagamento.",
    tip: "Consulte o pedido no aplicativo oficial.",
  },
  {
    icon: "0800",
    title: "Falsa central bancária",
    text: "Criminosos simulam atendimentos urgentes e tentam induzir transferências ou obter senhas.",
    tip: "Desligue e procure seu banco diretamente.",
  },
];

function cleanAnalysis(value = "") {
  return value
    .replace(/:red\[|:green\[|:orange\[|:blue\[/g, "")
    .replace(/\*\*/g, "")
    .replace(/\]$/gm, "")
    .replace(/^#{1,4}\s*/gm, "")
    .trim();
}

export default function Home() {
  const [mode, setMode] = useState<Mode>("message");
  const [text, setText] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Analysis | null>(null);
  const [error, setError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const resultRef = useRef<HTMLElement>(null);

  const ready = mode === "message" || mode === "link"
    ? text.trim().length >= 4
    : mode === "password"
      ? password.length > 0
      : Boolean(file);

  useEffect(() => {
    if (result) resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [result]);

  function changeMode(nextMode: Mode) {
    setMode(nextMode);
    setResult(null);
    setError("");
  }

  function selectFile(candidate?: File) {
    setError("");
    if (!candidate) return;
    const allowed = candidate.type.startsWith("image/") || candidate.type === "application/pdf";
    if (!allowed) return setError("Envie uma imagem PNG, JPG, WEBP ou um arquivo PDF.");
    if (candidate.size > 4 * 1024 * 1024) return setError("Nesta interface, o tamanho máximo do arquivo é 4 MB.");
    setFile(candidate);
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!ready || loading) return;
    setLoading(true);
    setError("");
    setResult(null);

    try {
      let response: Response;
      if (mode === "file" && file) {
        const form = new FormData();
        form.append("file", file);
        response = await fetch("/api/backend/api/v1/analyze-file?source=web_next", { method: "POST", body: form });
      } else {
        const endpoint = mode === "password" ? "check-password" : "analyze";
        const body = mode === "password" ? { password } : { text, source: "web_next" };
        response = await fetch(`/api/backend/api/v1/${endpoint}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
        });
      }
      const data = await readApiResponse(response);
      if (!response.ok) throw new Error(data.detail || "Não foi possível concluir a análise.");
      setResult(data);
      if (mode === "password") setPassword("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erro inesperado. Tente novamente.");
    } finally {
      setLoading(false);
    }
  }

  function resetAnalysis() {
    setResult(null);
    setText("");
    setPassword("");
    setFile(null);
    setError("");
    document.querySelector("#verificador")?.scrollIntoView({ behavior: "smooth" });
  }

  const resultLevel = result?.breached ? "danger" : result?.level || "safe";
  const resultTitle = result?.breached === true
    ? "Senha encontrada em vazamentos"
    : result?.breached === false
      ? "Nenhum vazamento conhecido"
      : result?.verdict === "GOLPE"
        ? "Possível golpe detectado"
        : result?.verdict === "ALERTA"
          ? "Sinais de alerta encontrados"
          : result?.verdict === "SEGURO"
            ? "Baixo risco identificado"
            : "Análise concluída";
  const resultScore = Math.max(0, Math.min(100, result?.score ?? (result?.breached ? 10 : 100)));
  const resultText = result?.message || cleanAnalysis(result?.analysis);

  return (
    <>
      <header className="topbar">
        <a className="brand" href="#inicio" aria-label="É Golpe? — início">
          <span className="brand-mark" aria-hidden="true">?</span>
          <span><strong>É Golpe?</strong><small>Proteção digital</small></span>
        </a>
        <nav className="desktop-nav" aria-label="Navegação principal">
          <a href="#inicio">Início</a>
          <a href="#verificador">Verificador</a>
          <a href="#orientacoes">Orientações</a>
        </nav>
        <a className="sos-link" href="#socorro"><span aria-hidden="true">!</span> SOS Golpe</a>
      </header>

      <main id="inicio">
        <section className="intro" aria-labelledby="page-title">
          <div className="intro-copy">
            <span className="live-badge"><i aria-hidden="true" /> Proteção ativa</span>
            <h1 id="page-title">Antes de clicar,<br /><em>verifique.</em></h1>
            <p>Cole uma mensagem, envie um link ou anexe um arquivo suspeito. A análise combina inteligência artificial e sinais técnicos para ajudar você a decidir com mais segurança.</p>
            <div className="trust-list" aria-label="Características do serviço">
              <span>✓ Fácil de usar</span>
              <span>✓ Resultado em linguagem clara</span>
              <span>✓ Funciona no celular e computador</span>
            </div>
          </div>

          <section className="checker" id="verificador" aria-labelledby="checker-title">
            <div className="checker-heading">
              <div>
                <span className="section-kicker">VERIFICAÇÃO INTELIGENTE</span>
                <h2 id="checker-title">O que você quer analisar?</h2>
              </div>
              <span className="online-label"><i aria-hidden="true" /> Online</span>
            </div>

            <div className="mode-tabs" role="tablist" aria-label="Tipo de análise">
              {modes.map((item) => (
                <button key={item.id} className={mode === item.id ? "active" : ""} onClick={() => changeMode(item.id)} role="tab" aria-selected={mode === item.id} type="button">
                  <span className="mode-icon" aria-hidden="true">{item.icon}</span>
                  <strong>{item.label}</strong>
                  <small>{item.hint}</small>
                </button>
              ))}
            </div>

            <form onSubmit={submit} className="form-area">
              {(mode === "message" || mode === "link") && (
                <label className="field-label">
                  {mode === "link" ? "COLE O ENDEREÇO DO SITE" : "COLE A MENSAGEM SUSPEITA"}
                  <textarea
                    value={text}
                    onChange={(event) => setText(event.target.value)}
                    placeholder={mode === "link" ? "https://site-que-voce-recebeu.com" : "Ex.: Sua conta será bloqueada. Regularize agora no link..."}
                    maxLength={8000}
                    autoFocus
                    inputMode={mode === "link" ? "url" : "text"}
                  />
                  <span className="counter">{text.length}/8000</span>
                </label>
              )}

              {mode === "file" && (
                <div
                  className={`dropzone ${dragging ? "dragging" : ""}`}
                  onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
                  onDragLeave={() => setDragging(false)}
                  onDrop={(event) => { event.preventDefault(); setDragging(false); selectFile(event.dataTransfer.files[0]); }}
                  onClick={() => inputRef.current?.click()}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(event) => (event.key === "Enter" || event.key === " ") && inputRef.current?.click()}
                >
                  <input ref={inputRef} type="file" accept="image/png,image/jpeg,image/webp,application/pdf" hidden onChange={(event: ChangeEvent<HTMLInputElement>) => selectFile(event.target.files?.[0])} />
                  <span className="upload-icon" aria-hidden="true">＋</span>
                  <strong>{file ? file.name : "Envie uma foto, print ou PDF"}</strong>
                  <span>{file ? `${(file.size / 1024 / 1024).toFixed(2)} MB` : "Toque para escolher ou arraste o arquivo · até 4 MB"}</span>
                </div>
              )}

              {mode === "password" && (
                <div className="password-block">
                  <label className="field-label" htmlFor="password-check">DIGITE A SENHA PARA CONSULTA</label>
                  <div className="password-field">
                    <input id="password-check" type={showPassword ? "text" : "password"} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Sua senha não será armazenada" autoComplete="off" autoFocus />
                    <button type="button" onClick={() => setShowPassword((current) => !current)} aria-label={showPassword ? "Ocultar senha" : "Mostrar senha"}>{showPassword ? "Ocultar" : "Mostrar"}</button>
                  </div>
                  <p className="privacy-note"><span aria-hidden="true">◆</span> A consulta externa usa somente uma parte irreversível do hash da senha.</p>
                </div>
              )}

              {error && <div className="error" role="alert"><strong>Não foi possível analisar.</strong> {error}</div>}
              <button className="analyze-button" disabled={!ready || loading}>
                {loading ? <><span className="spinner" /> Analisando sinais...</> : <>Analisar agora <span aria-hidden="true">→</span></>}
              </button>
              <p className="form-notice">Não informe códigos de confirmação, dados bancários ou documentos pessoais no campo de texto.</p>
            </form>
          </section>
        </section>

        {result && (
          <section ref={resultRef} className={`result-card ${resultLevel}`} id="resultado" aria-live="polite" tabIndex={-1}>
            <div className="result-summary">
              <span className="result-label">RESULTADO DA VERIFICAÇÃO</span>
              <div className="score-ring" style={{ "--score": `${resultScore * 3.6}deg` } as React.CSSProperties} aria-label={`Pontuação de segurança: ${resultScore} de 100`}>
                <div><strong>{resultScore}</strong><small>de 100</small></div>
              </div>
              <span className="score-caption">Pontuação de segurança</span>
            </div>
            <div className="result-content">
              <span className="result-status">{result?.icon || (resultLevel === "danger" ? "🚨" : resultLevel === "warning" ? "⚠️" : "✅")} {result?.verdict || (result?.breached ? "ALERTA" : "CONCLUÍDO")}</span>
              <h2>{resultTitle}</h2>
              {result.cached && <span className="cache-badge">Resultado verificado anteriormente</span>}
              <div className="analysis-text">{resultText}</div>
              <div className="result-actions">
                <button type="button" className="primary-action" onClick={() => navigator.clipboard.writeText(resultText)}>Copiar resultado</button>
                <button type="button" onClick={resetAnalysis}>Fazer nova análise</button>
              </div>
            </div>
          </section>
        )}

        <section className="how-it-works" aria-labelledby="how-title">
          <div className="section-heading">
            <span className="section-kicker">SIMPLES E DIRETO</span>
            <h2 id="how-title">Você não precisa entender de tecnologia</h2>
            <p>O É Golpe? organiza os sinais encontrados e mostra o que merece sua atenção.</p>
          </div>
          <div className="steps">
            <article><b>1</b><div><h3>Você envia</h3><p>Uma mensagem, link, imagem ou documento que despertou desconfiança.</p></div></article>
            <article><b>2</b><div><h3>O sistema investiga</h3><p>A IA cruza o conteúdo com sinais técnicos e padrões conhecidos de fraude.</p></div></article>
            <article><b>3</b><div><h3>Você recebe orientação</h3><p>Veja uma pontuação, um parecer claro e os cuidados recomendados.</p></div></article>
          </div>
        </section>

        <section className="warnings" id="orientacoes" aria-labelledby="warning-title">
          <div className="section-heading horizontal">
            <div><span className="section-kicker">FIQUE ATENTO</span><h2 id="warning-title">Golpes frequentes</h2></div>
            <p>Reconheça alguns padrões comuns antes de agir por impulso.</p>
          </div>
          <div className="warning-grid">
            {warningCards.map((card) => (
              <article key={card.title}>
                <span className="warning-icon" aria-hidden="true">{card.icon}</span>
                <h3>{card.title}</h3>
                <p>{card.text}</p>
                <strong>✓ {card.tip}</strong>
              </article>
            ))}
          </div>
        </section>

        <section className="sos-card" id="socorro" aria-labelledby="sos-title">
          <div className="sos-mark" aria-hidden="true">!</div>
          <div>
            <span className="section-kicker">SE VOCÊ JÁ CAIU EM UM GOLPE</span>
            <h2 id="sos-title">Aja com calma e procure os canais oficiais</h2>
            <p>Interrompa o contato com o suspeito, avise seu banco pelo aplicativo oficial ou pelo telefone impresso no cartão e preserve mensagens e comprovantes.</p>
          </div>
          <a href="https://www.gov.br/pt-br/servicos/registrar-boletim-de-ocorrencia-policial" target="_blank" rel="noreferrer">Consultar delegacia eletrônica <span aria-hidden="true">↗</span></a>
        </section>
      </main>

      <footer>
        <div className="footer-inner">
          <div className="brand footer-brand"><span className="brand-mark" aria-hidden="true">?</span><span><strong>É Golpe?</strong><small>Uma iniciativa Serviços IA</small></span></div>
          <p>Ferramenta automatizada de apoio à decisão. Em caso de dúvida, não clique, não pague e procure a instituição por seus canais oficiais.</p>
          <a href="https://ia-contra-fraude.fly.dev/docs" target="_blank" rel="noreferrer">Documentação da API</a>
        </div>
      </footer>

      <nav className="mobile-nav" aria-label="Navegação para celular">
        <a href="#inicio"><span aria-hidden="true">⌂</span>Início</a>
        <a href="#verificador"><span aria-hidden="true">⌕</span>Verificar</a>
        <a href="#orientacoes"><span aria-hidden="true">i</span>Dicas</a>
        <a href="#socorro"><span aria-hidden="true">!</span>SOS</a>
      </nav>
    </>
  );
}
