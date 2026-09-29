import { useEffect, useRef, useState } from "react";
import Tester from "./Tester.jsx";
import "./console.css";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
const REFRESH_MS = 3000;

const EVENT_LABELS = {
  allowed: { label: "autorisée", color: "var(--accent-safe)" },
  sanitized: { label: "assainie · PII", color: "var(--accent-warn)" },
  blocked_pii: { label: "bloquée · PII", color: "var(--accent-danger)" },
  blocked_injection: { label: "bloquée · règles", color: "var(--accent-danger)" },
  blocked_injection_ia: { label: "bloquée · IA (2e couche)", color: "var(--accent-purple)" },
  error: { label: "erreur", color: "var(--accent-danger)" },
};

function formatTime(ts) {
  const d = new Date(ts * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function useFirewallData() {
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [health, setHealth] = useState(null);
  const [connectionError, setConnectionError] = useState(false);
  const firstLoad = useRef(true);
  const pollRef = useRef(() => {});

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const [statsRes, eventsRes, healthRes] = await Promise.all([
          fetch(`${API_URL}/v1/admin/stats`),
          fetch(`${API_URL}/v1/admin/events?limit=25`),
          fetch(`${API_URL}/health`),
        ]);
        if (!statsRes.ok || !eventsRes.ok || !healthRes.ok) throw new Error("réponse non-OK");
        const statsData = await statsRes.json();
        const eventsData = await eventsRes.json();
        const healthData = await healthRes.json();
        if (!cancelled) {
          setStats(statsData);
          setEvents(eventsData);
          setHealth(healthData);
          setConnectionError(false);
        }
      } catch {
        if (!cancelled) setConnectionError(true);
      } finally {
        firstLoad.current = false;
      }
    }

    pollRef.current = poll;
    poll();
    const id = setInterval(poll, REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  return { stats, events, health, connectionError, loading: firstLoad.current, refresh: () => pollRef.current() };
}

function StatCell({ value, label }) {
  return (
    <div className="stat-cell">
      <div className="stat-value">{value ?? "—"}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function ChainBadge({ valid, loading }) {
  if (loading) return <span className="chain-badge chain-badge--pending">Vérification…</span>;
  return (
    <span className={`chain-badge ${valid ? "chain-badge--ok" : "chain-badge--broken"}`}>
      <span className="chain-dot" />
      {valid ? "Chaîne d'audit intacte" : "Intégrité compromise"}
    </span>
  );
}

function LayersBadge({ health, loading }) {
  if (loading || !health) return null;
  const classifierOn = !!health.classifier_enabled;
  return (
    <div className="layers-badge" role="group" aria-label="Couches de défense actives">
      <span className="layer-pill layer-pill--on" title="Détection par règles pondérées (toujours active)">
        <span className="layer-dot" />
        1 · Règles
      </span>
      <span
        className={`layer-pill ${classifierOn ? "layer-pill--on layer-pill--ia" : "layer-pill--off"}`}
        title={classifierOn
          ? `Classifieur IA actif (${health.classifier_provider}/${health.classifier_model})`
          : "Classifieur IA inactif — aucune clé API configurée (voir .env.example)"}
      >
        <span className="layer-dot" />
        2 · IA {classifierOn ? "active" : "inactive"}
      </span>
    </div>
  );
}

export default function App() {
  const { stats, events, health, connectionError, loading, refresh } = useFirewallData();

  return (
    <div className="console">
      <header className="console-header">
        <div className="console-header__brand">
          <span className="brand-mark" aria-hidden="true">◆</span>
          <div>
            <h1>AI Firewall &amp; Compliance</h1>
            <p className="subtitle">console de supervision · proxy IA — projet INF4173</p>
          </div>
        </div>
        <div className="console-header__badges">
          <LayersBadge health={health} loading={loading} />
          <ChainBadge valid={stats?.chain_valid} loading={loading} />
        </div>
      </header>

      {connectionError && (
        <div className="banner-error">
          Impossible de joindre l'API à {API_URL}. Vérifiez que le proxy tourne (uvicorn app.main:app --reload).
        </div>
      )}

      <section className="stat-strip" aria-label="Statistiques globales">
        <StatCell value={stats?.total_requests} label="requêtes totales" />
        <StatCell value={stats?.allowed} label="autorisées" />
        <StatCell value={stats?.sanitized} label="assainies (PII)" />
        <StatCell value={stats?.blocked_injection} label="bloquées · injection" />
        <StatCell value={stats?.blocked_pii} label="bloquées · PII" />
        <StatCell value={stats?.errors} label="erreurs" />
      </section>

      <div className="two-col">
        <Tester onSent={refresh} />

        <section className="log-panel">
          <div className="log-panel__header">
            <h2>Journal d'événements</h2>
            <span className="live-dot" aria-hidden="true" />
            <span className="live-label">en direct</span>
          </div>

          {events.length === 0 && !loading ? (
            <div className="empty-state">
              Aucun événement pour l'instant. Utilisez le panneau « Tester une requête » à gauche pour envoyer votre premier appel.
            </div>
          ) : (
            <div className="log-table" role="table">
              <div className="log-row log-row--head" role="row">
                <span>heure</span>
                <span>requête</span>
                <span>événement</span>
                <span>détail</span>
              </div>
              {events.map((e) => {
                const meta = EVENT_LABELS[e.event_type] || { label: e.event_type, color: "var(--text-muted)" };
                return (
                  <div className="log-row" role="row" key={e.id} style={{ borderLeftColor: meta.color }}>
                    <span className="mono">{formatTime(e.timestamp)}</span>
                    <span className="mono muted">{e.request_id.slice(0, 8)}</span>
                    <span style={{ color: meta.color }}>{meta.label}</span>
                    <span className="muted">{e.detail}</span>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
