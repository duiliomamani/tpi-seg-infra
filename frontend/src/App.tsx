import { FormEvent, KeyboardEvent, useEffect, useRef, useState } from "react";

type Profile = {
  authenticated: boolean;
  name: string;
  email: string;
  roles: string[];
  consented_tools: string[];
  model_consent: boolean;
  model_configured: boolean;
  model_local: boolean;
  model_name?: string | null;
  csrf_token: string;
};

type ChatResult = {
  kind: "message" | "tool_consent" | "pending_action";
  text?: string;
  message?: string;
  tool?: string;
  sources?: { id: string; title: string }[];
  model_status?: string;
  action_id?: string;
  summary?: string;
  description?: string;
  expires_at?: number;
};

type Message = {
  id: string;
  role: "user" | "assistant";
  text: string;
  sources?: { id: string; title: string }[];
  tool?: string;
  resumeMessage?: string;
  actionId?: string;
  summary?: string;
  description?: string;
  actionState?: "pending" | "confirmed" | "cancelled";
  modelStatus?: string;
};

const READ_TOOLS = [
  { id: "search_kb", title: "Buscar artículos", description: "Consulta artículos de soporte aprobados." },
  { id: "get_my_ticket", title: "Consultar tickets", description: "Comprueba propiedad o asignación antes de devolver un ticket." },
];

async function getError(response: Response): Promise<string> {
  try {
    const payload = await response.json();
    return typeof payload.detail === "string" ? payload.detail : "No se pudo completar la solicitud.";
  } catch {
    return "No se pudo completar la solicitud.";
  }
}

function initials(name: string): string {
  return name.split(/\s+/).slice(0, 2).map((part) => part[0] ?? "").join("").toUpperCase();
}

export default function App() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [loadingProfile, setLoadingProfile] = useState(true);
  const [messages, setMessages] = useState<Message[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const endOfMessages = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const loadProfile = async () => {
    setLoadingProfile(true);
    try {
      const response = await fetch("/api/me", { credentials: "same-origin" });
      if (!response.ok) {
        setProfile(null);
        return;
      }
      const data = (await response.json()) as Profile;
      setProfile(data);
    } catch {
      setProfile(null);
      setError("No pude conectar con el servicio local.");
    } finally {
      setLoadingProfile(false);
    }
  };

  useEffect(() => {
    void loadProfile();
  }, []);

  useEffect(() => {
    endOfMessages.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages, busy]);

  const api = async <T,>(path: string, body?: unknown): Promise<T> => {
    if (!profile) throw new Error("Iniciá sesión para continuar.");
    const response = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      credentials: "same-origin",
      headers: body === undefined ? {} : {
        "Content-Type": "application/json",
        "X-CSRF-Token": profile.csrf_token,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) {
      if (response.status === 401) setProfile(null);
      throw new Error(await getError(response));
    }
    return response.status === 204 ? ({} as T) : (await response.json()) as T;
  };

  const addAssistant = (result: ChatResult, originalMessage: string) => {
    if (result.kind === "tool_consent") {
      setMessages((current) => [...current, {
        id: crypto.randomUUID(), role: "assistant", text: result.message ?? "",
        tool: result.tool, resumeMessage: originalMessage,
      }]);
      return;
    }
    if (result.kind === "pending_action") {
      setMessages((current) => [...current, {
        id: crypto.randomUUID(), role: "assistant", text: result.message ?? "",
        actionId: result.action_id, summary: result.summary, description: result.description,
        actionState: "pending",
      }]);
      return;
    }
    setMessages((current) => [...current, {
      id: crypto.randomUUID(), role: "assistant", text: result.text ?? "",
      sources: result.sources, modelStatus: result.model_status,
    }]);
  };

  const sendToAgent = async (message: string) => {
    setBusy(true);
    setError("");
    try {
      const result = await api<ChatResult>("/api/chat", { message });
      addAssistant(result, message);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "No se pudo enviar el mensaje.");
    } finally {
      setBusy(false);
      inputRef.current?.focus();
    }
  };

  const submitMessage = async (event?: FormEvent, preset?: string) => {
    event?.preventDefault();
    const text = (preset ?? draft).trim();
    if (!text || busy || !profile) return;
    setDraft("");
    setMessages((current) => [...current, { id: crypto.randomUUID(), role: "user", text }]);
    await sendToAgent(text);
  };

  const grantTool = async (message: Message) => {
    if (!message.tool || !message.resumeMessage) return;
    setBusy(true);
    setError("");
    try {
      await api("/api/consent/tool", { tool: message.tool, allowed: true });
      setProfile((current) => current ? {
        ...current,
        consented_tools: Array.from(new Set([...current.consented_tools, message.tool!])),
      } : current);
      setMessages((current) => current.filter((item) => item.id !== message.id));
      await sendToAgent(message.resumeMessage);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "No se pudo actualizar el permiso.");
      setBusy(false);
    }
  };

  const changeToolConsent = async (tool: string, allowed: boolean) => {
    try {
      const result = await api<{ consented_tools: string[] }>("/api/consent/tool", { tool, allowed });
      setProfile((current) => current ? { ...current, consented_tools: result.consented_tools } : current);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "No se pudo actualizar el permiso.");
    }
  };

  const changeModelConsent = async (allowed: boolean) => {
    try {
      const result = await api<{ model_consent: boolean }>("/api/consent/model", { allowed });
      setProfile((current) => current ? { ...current, model_consent: result.model_consent } : current);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "No se pudo actualizar el permiso.");
    }
  };

  const updateAction = (messageId: string, property: "summary" | "description", value: string) => {
    setMessages((current) => current.map((item) => item.id === messageId ? { ...item, [property]: value } : item));
  };

  const confirmAction = async (message: Message) => {
    if (!message.actionId || !message.summary || !message.description) return;
    setBusy(true);
    setError("");
    try {
      const result = await api<ChatResult>(`/api/actions/${encodeURIComponent(message.actionId)}/confirm`, {
        summary: message.summary,
        description: message.description,
      });
      setMessages((current) => current.map((item) => item.id === message.id ? { ...item, actionState: "confirmed" } : item));
      addAssistant(result, "");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "No se pudo confirmar el ticket.");
    } finally {
      setBusy(false);
    }
  };

  const cancelAction = async (message: Message) => {
    if (!message.actionId) return;
    try {
      await api(`/api/actions/${encodeURIComponent(message.actionId)}/cancel`, {});
      setMessages((current) => current.map((item) => item.id === message.id ? { ...item, actionState: "cancelled" } : item));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "No se pudo cancelar la acción.");
    }
  };

  const logout = async () => {
    try {
      await api("/auth/logout", {});
    } catch {
      // The local session is also cleared if the identity provider is unavailable.
    }
    setProfile(null);
    setMessages([]);
  };

  const onInputKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void submitMessage();
    }
  };

  if (loadingProfile) {
    return <main className="loading-screen"><span className="brand-mark">S</span><span>Cargando mesa de ayuda…</span></main>;
  }

  if (!profile) {
    return (
      <main className="login-screen">
        <section className="login-card">
          <div className="brand-lockup"><span className="brand-mark">S</span><span>soporte<span className="brand-dot">.</span></span></div>
          <div className="login-illustration" aria-hidden="true"><div className="orbit orbit-one" /><div className="orbit orbit-two" /><span className="headset">◖</span><span className="spark spark-a">✦</span><span className="spark spark-b">✳</span></div>
          <p className="eyebrow">MESA DE AYUDA INTERNA</p>
          <h1>¿En qué podemos ayudarte?</h1>
          <p className="login-copy">Ingresá con tu cuenta para consultar la base de soporte o revisar tus tickets.</p>
          {error && <div className="error-banner">{error}</div>}
          <a className="primary-button login-button" href="/auth/login">Continuar con mi cuenta <span aria-hidden="true">→</span></a>
          <p className="privacy-note"><span className="lock-icon">⌑</span> Sesión protegida · acceso verificado por tu organización</p>
        </section>
        <footer className="login-footer">PoC local de soporte seguro <span>·</span> No uses datos reales</footer>
      </main>
    );
  }

  const roleLabel = profile.roles.includes("support_l1") ? "Soporte L1" : "Colaborador/a";
  const hasConversation = messages.length > 1;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup"><span className="brand-mark">S</span><span>soporte<span className="brand-dot">.</span></span></div>
        <button className="mobile-permissions" onClick={() => setSettingsOpen((open) => !open)} aria-label="Abrir permisos de sesión">◈</button>
        <div className="sidebar-workspace"><span className="workspace-icon">⌂</span><div><strong>Mesa de ayuda</strong><small>Soporte interno</small></div><span className="chevron">⌄</span></div>
        <button className="new-chat-button" onClick={() => { setMessages([]); setError(""); }}>
          <span>＋</span> Nueva consulta <kbd>⌘ K</kbd>
        </button>
        <div className="sidebar-label">TU ESPACIO</div>
        <div className="sidebar-links"><div className="sidebar-link active"><span>◉</span> Conversación actual</div><button className="sidebar-link" onClick={() => setSettingsOpen((open) => !open)}><span>♧</span> Permisos de sesión <span className="link-chevron">{settingsOpen ? "⌃" : "⌄"}</span></button></div>
        {settingsOpen && <section className={`permission-panel ${settingsOpen ? "open" : ""}`}>
          <p className="permission-heading">Lecturas autorizadas</p>
          {READ_TOOLS.map((tool) => {
            const granted = profile.consented_tools.includes(tool.id);
            return <div className="permission-row" key={tool.id}><div><strong>{tool.title}</strong><small>{tool.description}</small></div><button className={granted ? "text-button revoke" : "text-button"} onClick={() => void changeToolConsent(tool.id, !granted)}>{granted ? "Revocar" : "Sin permiso"}</button></div>;
          })}
          {profile.model_configured && <div className="model-consent">
            <p className="permission-heading">Procesamiento con {profile.model_local ? "modelo local" : "modelo externo"}</p>
            <p>{profile.model_local
              ? `Si das permiso, tu mensaje y los fragmentos autorizados se procesarán en Ollama local (${profile.model_name}).`
              : `Si das permiso, se enviarán tu mensaje y los fragmentos autorizados al proveedor configurado (${profile.model_name}).`}</p>
            <label className="switch-row"><span>{profile.model_consent ? "Autorizado en esta sesión" : "No autorizado"}</span><input type="checkbox" checked={profile.model_consent} onChange={(event) => void changeModelConsent(event.target.checked)} /><span className="switch" /></label>
          </div>}
          {!profile.model_configured && <p className="local-model-note">El agente funciona localmente. No hay un modelo externo configurado.</p>}
        </section>}
        <div className="sidebar-bottom">
          <div className="security-note"><span className="shield-icon">◇</span><div><strong>Canal protegido</strong><small>Los permisos se verifican en cada consulta.</small></div></div>
          <div className="profile-row"><span className="avatar">{initials(profile.name)}</span><div className="profile-details"><strong>{profile.name}</strong><small>{roleLabel}</small></div><button className="logout-button" title="Cerrar sesión" aria-label="Cerrar sesión" onClick={() => void logout()}>↪</button></div>
        </div>
      </aside>

      <main className="chat-workspace">
        <header className="topbar"><div className="breadcrumbs"><span>Soporte</span><span className="crumb-divider">/</span><strong>Conversación</strong></div><div className="topbar-status"><span className="status-dot" /> Sesión segura <span className="topbar-divider" /> <span className="role-pill">{roleLabel}</span></div></header>
        <section className={`conversation ${hasConversation ? "has-conversation" : ""}`}>
          {!hasConversation && <div className="welcome-block"><span className="welcome-icon">✳</span><p className="eyebrow">ASISTENTE DE SOPORTE</p><h1>Hola, {profile.name.split(" ")[0]} <span>👋</span></h1><p>Contame qué te pasa. Te ayudo a encontrar una solución o a preparar un ticket.</p></div>}
          <div className="messages" aria-live="polite">
            {messages.map((message) => <article className={`message-row ${message.role}`} key={message.id}>
              <div className={`message-avatar ${message.role}`}>{message.role === "assistant" ? <span>✳</span> : initials(profile.name)}</div>
              <div className="message-content">
                {message.role === "assistant" && <div className="message-author">Asistente <span>·</span> ahora</div>}
                {!message.tool && <div className={`bubble ${message.role}`}>{message.text}</div>}
                {message.tool && <div className="consent-card"><div className="consent-icon">◈</div><div className="consent-content"><strong>Permiso de lectura</strong><p>{message.text}</p><div className="consent-actions"><button className="small-primary" disabled={busy} onClick={() => void grantTool(message)}>Autorizar y continuar</button><button className="small-secondary" onClick={() => setMessages((current) => current.filter((item) => item.id !== message.id))}>Ahora no</button></div></div></div>}
                {message.actionId && <div className={`action-card ${message.actionState === "confirmed" ? "completed" : ""}`}>
                  <div className="action-card-header"><span className="action-icon">＋</span><div><strong>{message.actionState === "confirmed" ? "Ticket creado" : message.actionState === "cancelled" ? "Acción cancelada" : "Revisá el ticket"}</strong><small>Se enviará a la cola de soporte de red</small></div><span className="pending-badge">{message.actionState === "pending" ? "A confirmar" : message.actionState === "confirmed" ? "Completado" : "Cancelado"}</span></div>
                  {message.actionState === "pending" && <div className="action-fields"><label>Resumen<input value={message.summary ?? ""} maxLength={120} onChange={(event) => updateAction(message.id, "summary", event.target.value)} /></label><label>Descripción<textarea value={message.description ?? ""} maxLength={700} rows={3} onChange={(event) => updateAction(message.id, "description", event.target.value)} /></label></div>}
                  {message.actionState === "pending" && <div className="action-footer"><span>La confirmación vence en unos minutos.</span><div><button className="small-secondary" disabled={busy} onClick={() => void cancelAction(message)}>Cancelar</button><button className="small-primary" disabled={busy} onClick={() => void confirmAction(message)}>Confirmar creación <span>→</span></button></div></div>}
                </div>}
                {message.sources && message.sources.length > 0 && <div className="source-list"><span>Fuentes consultadas</span>{message.sources.map((source) => <span className="source-chip" key={source.id}><span className="source-icon">▤</span>{source.title}<small>{source.id}</small></span>)}</div>}
                {message.modelStatus === "not-consented" && <div className="local-only-note">Respondí con el agente local; tu mensaje no se envió a {profile.model_local ? "Ollama" : "el proveedor externo"}. Podés revisar el permiso en “Permisos de sesión”.</div>}
              </div>
            </article>)}
            {busy && <div className="typing-row"><span className="message-avatar assistant">✳</span><div className="typing-indicator"><i /><i /><i /></div></div>}
            <div ref={endOfMessages} />
          </div>
          {!hasConversation && <div className="suggestions"><button onClick={() => void submitMessage(undefined, "No puedo conectarme a la VPN desde casa")}>◉ <span>No puedo conectarme a la VPN</span><span className="suggestion-arrow">↗</span></button><button onClick={() => void submitMessage(undefined, "Quiero revisar el estado de mi ticket T-102")}>▧ <span>Consultar el estado de un ticket</span><span className="suggestion-arrow">↗</span></button><button onClick={() => void submitMessage(undefined, "Necesito abrir un ticket por problemas de conectividad")}>＋ <span>Crear un ticket de soporte</span><span className="suggestion-arrow">↗</span></button></div>}
        </section>
        <div className="composer-wrap">
          {error && <div className="error-banner chat-error"><span>!</span>{error}<button onClick={() => setError("")} aria-label="Cerrar aviso">×</button></div>}
          <form className="composer" onSubmit={(event) => void submitMessage(event)}>
            <textarea ref={inputRef} value={draft} onChange={(event) => setDraft(event.target.value)} onKeyDown={onInputKeyDown} maxLength={1200} rows={1} placeholder="Escribí tu consulta…" aria-label="Escribí tu consulta" disabled={busy} />
            <div className="composer-bottom"><div className="composer-hint"><span className="lock-icon">⌑</span> No compartas contraseñas ni códigos de verificación <span className="char-count">{draft.length}/1200</span></div><button className="send-button" type="submit" disabled={busy || !draft.trim()} aria-label="Enviar mensaje">↑</button></div>
          </form>
          <p className="composer-caption">El asistente puede equivocarse. Verificá los pasos antes de aplicarlos.</p>
        </div>
      </main>
    </div>
  );
}
