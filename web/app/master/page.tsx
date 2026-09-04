"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import Link from "next/link";

type Summary = { analyses: number; feedbacks: number; whitelist: number; blacklist: number };
type Domain = { id: number; domain: string; list_type: "whitelist" | "blacklist"; added_at: string };
type RecordItem = { id: number; timestamp: string; input?: string; output?: string; rating?: string };
type Tab = "overview" | "dataset" | "feedbacks" | "whitelist" | "blacklist" | "logs";

async function requestJson(path: string, init?: RequestInit) {
  const response = await fetch(path, { ...init, headers: { "content-type": "application/json", ...(init?.headers || {}) }, cache: "no-store" });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || "Não foi possível concluir a operação.");
  return data;
}

export default function MasterPage() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<Tab>("overview");
  const [summary, setSummary] = useState<Summary | null>(null);
  const [items, setItems] = useState<RecordItem[]>([]);
  const [domains, setDomains] = useState<Domain[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [newDomain, setNewDomain] = useState("");

  const loadTab = useCallback(async (selected: Tab) => {
    setLoading(true); setError("");
    try {
      if (selected === "overview") setSummary(await requestJson("/api/master/data/summary"));
      else if (selected === "dataset" || selected === "feedbacks") setItems((await requestJson(`/api/master/data/${selected}?limit=50`)).items);
      else if (selected === "whitelist" || selected === "blacklist") setDomains((await requestJson(`/api/master/data/domains?list_type=${selected}`)).items);
      else if (selected === "logs") setLogs((await requestJson("/api/master/data/logs")).lines);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Erro inesperado."); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetch("/api/master/session", { cache: "no-store" }).then((response) => { setAuthenticated(response.ok); if (response.ok) loadTab("overview"); }).catch(() => setAuthenticated(false)); }, [loadTab]);

  async function login(event: FormEvent) {
    event.preventDefault(); setLoading(true); setError("");
    try { await requestJson("/api/master/login", { method: "POST", body: JSON.stringify({ password }) }); setPassword(""); setAuthenticated(true); await loadTab("overview"); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Acesso negado."); }
    finally { setLoading(false); }
  }

  async function logout() { await fetch("/api/master/logout", { method: "POST" }); setAuthenticated(false); setSummary(null); }
  async function selectTab(selected: Tab) { setTab(selected); await loadTab(selected); }
  async function addDomain(event: FormEvent) {
    event.preventDefault();
    if (!newDomain.trim() || (tab !== "whitelist" && tab !== "blacklist")) return;
    try { await requestJson("/api/master/data/domains", { method: "POST", body: JSON.stringify({ domain: newDomain, list_type: tab }) }); setNewDomain(""); await loadTab(tab); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Erro ao salvar."); }
  }
  async function removeDomain(id: number) { if (!confirm("Remover este domínio da lista?")) return; await requestJson(`/api/master/data/domains/${id}`, { method: "DELETE" }); await loadTab(tab); }

  if (authenticated === null) return <main className="master-loading" aria-live="polite"><span className="spinner dark" /> Verificando sessão segura…</main>;
  if (!authenticated) return <main className="master-login"><form onSubmit={login} className="master-login-card"><Link href="/" className="master-brand"><span>?</span><strong>É Golpe?</strong></Link><small>ACESSO RESTRITO</small><h1>Área Master</h1><p>Digite sua senha administrativa. O acesso é protegido e a sessão expira automaticamente.</p><label>Senha<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" autoFocus required maxLength={256} /></label><button disabled={loading || !password}>{loading ? "Validando…" : "Entrar com segurança"}</button>{error && <div className="master-error" role="alert">{error}</div>}<Link href="/" className="master-back">← Voltar ao verificador</Link></form></main>;

  const tabs: { id: Tab; label: string }[] = [{ id: "overview", label: "Visão geral" }, { id: "dataset", label: "Análises" }, { id: "feedbacks", label: "Feedbacks" }, { id: "whitelist", label: "Whitelist" }, { id: "blacklist", label: "Blacklist" }, { id: "logs", label: "Logs" }];
  return <div className="master-shell"><aside className="master-sidebar"><Link href="/" className="master-brand"><span>?</span><strong>É Golpe?</strong></Link><div className="master-restricted">MASTER / SEGURO</div><nav>{tabs.map((entry) => <button key={entry.id} className={tab === entry.id ? "active" : ""} onClick={() => selectTab(entry.id)}>{entry.label}</button>)}</nav><button className="master-logout" onClick={logout}>Encerrar sessão</button></aside><main className="master-content"><header><div><small>PAINEL ADMINISTRATIVO</small><h1>{tabs.find((entry) => entry.id === tab)?.label}</h1></div><div className="master-actions"><Link href="/api/master/data/backup">Baixar backup</Link><span><i /> Sessão protegida</span></div></header>{error && <div className="master-error" role="alert">{error}</div>}{loading && <div className="master-progress">Atualizando dados…</div>}{tab === "overview" && summary && <section className="master-stats"><article><span>Análises</span><strong>{summary.analyses}</strong></article><article><span>Feedbacks</span><strong>{summary.feedbacks}</strong></article><article><span>Whitelist</span><strong>{summary.whitelist}</strong></article><article><span>Blacklist</span><strong>{summary.blacklist}</strong></article></section>}{(tab === "dataset" || tab === "feedbacks") && <section className="master-table"><div className="master-table-head"><span>Data</span><span>Conteúdo</span><span>Resultado</span></div>{items.map((item) => <article key={item.id}><time>{item.timestamp ? new Date(item.timestamp).toLocaleString("pt-BR") : "—"}</time><p>{item.input || "Sem conteúdo"}</p><strong>{item.output?.slice(0, 120) || item.rating || "—"}</strong></article>)}{!items.length && !loading && <p className="master-empty">Nenhum registro encontrado.</p>}</section>}{(tab === "whitelist" || tab === "blacklist") && <section><form className="domain-form" onSubmit={addDomain}><input placeholder="exemplo.com.br" value={newDomain} onChange={(event) => setNewDomain(event.target.value)} required /><button>Adicionar à {tab}</button></form><div className="domain-list">{domains.map((domain) => <article key={domain.id}><div><strong>{domain.domain}</strong><small>{domain.added_at ? new Date(domain.added_at).toLocaleString("pt-BR") : ""}</small></div><button onClick={() => removeDomain(domain.id)}>Remover</button></article>)}</div></section>}{tab === "logs" && <pre className="master-logs">{logs.join("") || "Nenhum log disponível."}</pre>}</main></div>;
}
