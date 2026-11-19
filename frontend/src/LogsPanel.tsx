import { useEffect, useMemo, useState } from "react";

type AuditEvent = {
  id: number;
  timestamp: string;
  category: "prompt" | "model" | "tool" | "policy" | "system";
  title: string;
  status: string;
  detail?: string;
  payload?: Record<string, unknown>;
};

type Filter = "all" | AuditEvent["category"];

const FILTERS: { id: Filter; label: string }[] = [
  { id: "all", label: "Todos" },
  { id: "prompt", label: "Prompts" },
  { id: "model", label: "Modelo" },
  { id: "tool", label: "Herramientas" },
  { id: "policy", label: "Política" },
  { id: "system", label: "Sistema" },
];

const CATEGORY_LABELS: Record<AuditEvent["category"], string> = {
  prompt: "PROMPT",
  model: "MODELO",
  tool: "HERRAMIENTA",
  policy: "POLÍTICA",
  system: "SISTEMA",
};

const STATUS_LABELS: Record<string, string> = {
  received: "RECIBIDO",
  running: "EN CURSO",
  proposed: "PROPUESTA",
  completed: "COMPLETADO",
  executed: "EJECUTADO",
  vulnerable: "VULNERABLE",
  blocked: "DENEGADO",
  rejected: "RECHAZADO",
  error: "ERROR",
  skipped: "OMITIDO",
  fallback: "RESPALDO",
  no_tool: "SIN HERRAMIENTA",
  awaiting_consent: "ESPERA DE CONSENTIMIENTO",
  awaiting_confirmation: "A CONFIRMAR",
  authorized: "AUTORIZADO",
  denied: "DENEGADO",
  cancelled: "CANCELADO",
};

function parseEvents(raw: string): AuditEvent[] {
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed)) return [];
  return parsed.filter((item): item is AuditEvent =>
    Boolean(item && typeof item === "object" && typeof item.id === "number" && typeof item.title === "string"),
  );
}

function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime())
    ? timestamp
    : new Intl.DateTimeFormat("es-AR", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(date);
}

export default function LogsPanel({ active }: { active: boolean }) {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [connection, setConnection] = useState<"off" | "connecting" | "live" | "retrying">("off");

  useEffect(() => {
    if (!active) {
      setConnection("off");
      return;
    }
    setConnection("connecting");
    const stream = new EventSource("/api/logs/stream");
    stream.onopen = () => setConnection("live");
    stream.onerror = () => setConnection("retrying");
    stream.addEventListener("snapshot", (event) => {
      try {
        const snapshot = parseEvents((event as MessageEvent<string>).data);
        setEvents(snapshot.slice(-300).reverse());
      } catch {
        setEvents([]);
      }
    });
    stream.addEventListener("log", (event) => {
      try {
        const incoming = JSON.parse((event as MessageEvent<string>).data) as AuditEvent;
        if (typeof incoming.id !== "number") return;
        setEvents((current) => [incoming, ...current.filter((item) => item.id !== incoming.id)].slice(0, 300));
      } catch {
        // An incomplete event is ignored; the stream will deliver the next event normally.
      }
    });
    return () => stream.close();
  }, [active]);

  const overview = useMemo(() => ({
    prompts: events.filter((event) => event.category === "prompt" || (event.category === "model" && event.title.toLowerCase().includes("prompt"))).length,
    tools: events.filter((event) => event.category === "tool").length,
    blocked: events.filter((event) => ["blocked", "denied", "rejected"].includes(event.status)).length,
  }), [events]);

  const visibleEvents = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase("es");
    return events.filter((event) => {
      if (filter !== "all" && event.category !== filter) return false;
      if (!normalizedQuery) return true;
      const content = `${event.title} ${event.detail ?? ""} ${JSON.stringify(event.payload ?? {})}`.toLocaleLowerCase("es");
      return content.includes(normalizedQuery);
    });
  }, [events, filter, query]);

  const connectionLabel = connection === "live"
    ? "En vivo"
    : connection === "retrying"
      ? "Reconectando"
      : connection === "connecting"
        ? "Conectando"
        : "En pausa";

  return <section className="logs-panel" aria-label="Registro de ejecución del agente">
    <header className="logs-heading">
      <div>
        <p className="logs-eyebrow">SESIÓN ACTUAL</p>
        <h1>Registro en vivo</h1>
        <p>Seguí cada consulta y las decisiones del agente, paso a paso.</p>
      </div>
      <span className={`logs-connection ${connection}`}><i />{connectionLabel}</span>
    </header>
    <div className="logs-privacy-note"><span aria-hidden="true">⌑</span><p><strong>Datos protegidos.</strong> Los tokens y códigos de aprobación se ocultan.</p></div>
    <div className="logs-overview" aria-label="Resumen del registro">
      <article><span>Eventos</span><strong>{events.length}<small>/300</small></strong></article>
      <article><span>Prompts</span><strong>{overview.prompts}</strong></article>
      <article><span>Herramientas</span><strong>{overview.tools}</strong></article>
      <article className={overview.blocked ? "has-alerts" : ""}><span>Bloqueos</span><strong>{overview.blocked}</strong></article>
    </div>
    <section className="logs-activity" aria-label="Actividad de la sesión">
      <div className="logs-activity-heading">
        <h2>Actividad</h2>
        <span>{visibleEvents.length} {visibleEvents.length === 1 ? "evento" : "eventos"}</span>
      </div>
      <div className="logs-toolbar">
        <div className="logs-filters" role="tablist" aria-label="Filtrar eventos">
          {FILTERS.map((item) => <button type="button" role="tab" aria-selected={filter === item.id} className={filter === item.id ? "selected" : ""} key={item.id} onClick={() => setFilter(item.id)}>{item.label}</button>)}
        </div>
        <label className="logs-search"><span aria-hidden="true">⌕</span><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Buscar en el registro" aria-label="Buscar en los eventos" /></label>
      </div>
    </section>
    <div className="logs-feed" aria-live="polite">
      {visibleEvents.length === 0 ? <div className="logs-empty"><span>◷</span><strong>{events.length ? "No hay coincidencias" : "Todavía no hay eventos"}</strong><p>{events.length ? "Probá con otro filtro o término de búsqueda." : "Volvé a Conversación y enviá una consulta para seguir el recorrido del agente."}</p></div> : visibleEvents.map((event) => <article className={`log-event ${event.category} ${event.status}`} key={event.id}>
        <div className="log-event-rail"><i /></div>
        <div className="log-event-body">
          <div className="log-event-topline"><span className={`log-category ${event.category}`}>{CATEGORY_LABELS[event.category] ?? "EVENTO"}</span><span className="log-event-number">#{event.id}</span><time dateTime={event.timestamp}>{formatTimestamp(event.timestamp)}</time><span className={`log-status ${event.status}`}>{STATUS_LABELS[event.status] ?? event.status.replaceAll("_", " ").toUpperCase()}</span></div>
          <h2>{event.title}</h2>
          {event.detail && (event.detail.length > 220 ? <details className="log-detail-more">
            <summary><span className="log-event-detail">{event.detail.slice(0, 220).trimEnd()}…</span><span className="log-detail-toggle">{event.category === "prompt" ? "Leer consulta completa" : "Leer detalle completo"}</span></summary>
            <p className="log-event-detail">{event.detail}</p>
          </details> : <p className="log-event-detail">{event.detail}</p>)}
          {event.payload && Object.keys(event.payload).length > 0 && <details className="log-payload"><summary><span>⌄</span> Ver prompt y datos del evento</summary><pre>{JSON.stringify(event.payload, null, 2)}</pre></details>}
        </div>
      </article>)}
    </div>
  </section>;
}
