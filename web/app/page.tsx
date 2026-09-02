"use client";

import { ChangeEvent, FormEvent, useMemo, useRef, useState } from "react";

type Mode = "message" | "file" | "password";
type Analysis = {
  verdict?: string;
  score?: number;
  level?: string;
  icon?: string;
  analysis?: string;
  breached?: boolean;
  message?: string;
  cached?: boolean;
  filename?: string;
};

const modes = [
  { id: "message" as const, icon: "⌁", label: "Mensagem ou link", hint: "SMS, WhatsApp, e-mail ou endereço web" },
  { id: "file" as const, icon: "▧", label: "Imagem ou PDF", hint: "Print, boleto ou documento suspeito" },
  { id: "password" as const, icon: "◈", label: "Senha vazada", hint: "Consulta anônima com k-anonymity" },
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
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Analysis | null>(null);
  const [error, setError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const ready = useMemo(() => {
    if (mode === "message") return text.trim().length >= 4;
    if (mode === "password") return password.length > 0;
    return Boolean(file);
  }, [mode, text, password, file]);

  function selectFile(candidate?: File) {
    setError("");
    if (!candidate) return;
    const allowed = candidate.type.startsWith("image/") || candidate.type === "application/pdf";
    if (!allowed) return setError("Envie uma imagem PNG, JPG, WEBP ou um arquivo PDF.");
    if (candidate.size > 4 * 1024 * 1024) {
      return setError("Nesta versão inicial, o novo portal aceita arquivos de até 4 MB. O sistema legado continua aceitando até 20 MB.");
    }
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
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Não foi possível concluir a análise.");
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erro inesperado. Tente novamente.");
    } finally {
      setLoading(false);
    }
  }

  const resultLevel = result?.breached ? "danger" : result?.level || "safe";
  const resultTitle = result?.breached === true ? "Senha encontrada em vazamentos" : result?.breached === false ? "Nenhum vazamento conhecido" : result?.verdict || "Análise concluída";
  const resultScore = Math.max(
    0,
    Math.min(100, result?.score ?? (result?.breached ? 10 : 100)),
  );

  return (
    <main>
      <div className="grid-bg" aria-hidden="true" />
      <div className="orb orb-one" aria-hidden="true" />
      <div className="orb orb-two" aria-hidden="true" />

      <header className="topbar">
        <a className="brand" href="#inicio" aria-label="É Golpe? Início">
          <span className="brand-mark">EG</span>
          <span><strong>É GOLPE?</strong><small>IA CONTRA FRAUDE</small></span>
        </a>
        <div className="status"><span /> SISTEMA OPERACIONAL</div>
      </header>

      <section className="hero" id="inicio">
        <div className="eyebrow"><span>●</span> VERIFICAÇÃO INTELIGENTE</div>
        <h1>Desconfie primeiro.<br /><em>Verifique em segundos.</em></h1>
        <p>Analise mensagens, links e documentos suspeitos antes de clicar, responder ou realizar qualquer pagamento.</p>
        <div className="trust-row">
          <span>✓ Análise com IA</span><span>✓ Fontes de segurança</span><span>✓ Privacidade em primeiro lugar</span>
        </div>
      </section>

      <section className="scanner" aria-labelledby="scanner-title">
        <div className="scanner-head">
          <div><span className="terminal-dot" /> CENTRAL DE VERIFICAÇÃO</div>
          <small>ESCOLHA O TIPO DE ANÁLISE</small>
        </div>

        <div className="mode-tabs" role="tablist" aria-label="Tipo de análise">
          {modes.map((item) => (
            <button key={item.id} className={mode === item.id ? "active" : ""} onClick={() => { setMode(item.id); setResult(null); setError(""); }} role="tab" aria-selected={mode === item.id}>
              <span className="mode-icon">{item.icon}</span><strong>{item.label}</strong><small>{item.hint}</small>
            </button>
          ))}
        </div>

        <form onSubmit={submit} className="form-area">
          {mode === "message" && (
            <label className="field-label">COLE O CONTEÚDO SUSPEITO
              <textarea value={text} onChange={(event) => setText(event.target.value)} placeholder="Ex.: Sua conta será bloqueada. Regularize agora em https://..." maxLength={8000} autoFocus />
              <span className="counter">{text.length}/8000</span>
            </label>
          )}

          {mode === "file" && (
            <div className={`dropzone ${dragging ? "dragging" : ""}`} onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={(e) => { e.preventDefault(); setDragging(false); selectFile(e.dataTransfer.files[0]); }} onClick={() => inputRef.current?.click()} role="button" tabIndex={0} onKeyDown={(e) => e.key === "Enter" && inputRef.current?.click()}>
              <input ref={inputRef} type="file" accept="image/png,image/jpeg,image/webp,application/pdf" hidden onChange={(e: ChangeEvent<HTMLInputElement>) => selectFile(e.target.files?.[0])} />
              <span className="upload-icon">⇧</span>
              <strong>{file ? file.name : "Arraste uma imagem ou PDF"}</strong>
              <span>{file ? `${(file.size / 1024 / 1024).toFixed(2)} MB` : "ou clique para selecionar · até 4 MB"}</span>
            </div>
          )}

          {mode === "password" && (
            <label className="field-label">DIGITE A SENHA PARA CONSULTA
              <input className="password-input" type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Sua senha não será armazenada" autoComplete="off" autoFocus />
              <span className="privacy-note">Somente uma parte irreversível do hash é consultada.</span>
            </label>
          )}

          {error && <div className="error" role="alert">{error}</div>}
          <button className="analyze-button" disabled={!ready || loading}>
            {loading ? <><span className="spinner" /> ANALISANDO SINAIS...</> : <>INICIAR VERIFICAÇÃO <span>→</span></>}
          </button>
        </form>
      </section>

      {result && (
        <section className={`result-card ${resultLevel}`} aria-live="polite">
          <div className="score-wrap">
            <div className="score-ring" style={{ "--score": `${resultScore * 3.6}deg` } as React.CSSProperties} aria-label={`Pontuação ${resultScore} de 100`}>
              <span>{resultScore}</span><small>DE 100</small>
            </div>
          </div>
          <div className="result-content">
            <small>RESULTADO DA VERIFICAÇÃO</small>
            <h2>{result.icon} {resultTitle}</h2>
            {result.cached && <span className="cache-badge">resultado verificado anteriormente</span>}
            <p>{result.message || cleanAnalysis(result.analysis)}</p>
            <div className="result-actions">
              <button type="button" onClick={() => navigator.clipboard.writeText(result.message || cleanAnalysis(result.analysis))}>Copiar resultado</button>
              <button type="button" onClick={() => { setResult(null); setText(""); setPassword(""); setFile(null); }}>Nova análise</button>
            </div>
          </div>
        </section>
      )}

      <section className="steps">
        <div><b>01</b><strong>Você envia</strong><p>Uma mensagem, link, imagem ou documento suspeito.</p></div>
        <div><b>02</b><strong>A IA investiga</strong><p>Cruzamos sinais técnicos e padrões conhecidos de fraude.</p></div>
        <div><b>03</b><strong>Você decide</strong><p>Receba um parecer simples e as ações recomendadas.</p></div>
      </section>

      <footer><span>É Golpe? — uma iniciativa Serviços IA</span><span>Não substitui orientação policial ou jurídica.</span></footer>
    </main>
  );
}
