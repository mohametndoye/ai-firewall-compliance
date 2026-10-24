import { useCallback, useEffect, useState } from "react";
import "./analysis.css";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
const REFRESH_MS = 5000;

// Une couleur par décision. Les trois blocages « rouges » de la console sont
// distingués ici, sinon la courbe empilée serait illisible.
const DECISIONS = [
  { key: "allowed", label: "Autorisées", color: "var(--accent-safe)" },
  { key: "sanitized", label: "Assainies (PII)", color: "var(--accent-warn)" },
  { key: "blocked_injection", label: "Bloquées · règles", color: "var(--accent-danger)" },
  { key: "blocked_injection_ia", label: "Bloquées · IA", color: "var(--accent-purple)" },
  { key: "blocked_pii", label: "Bloquées · PII", color: "color-mix(in srgb, var(--accent-danger) 55%, var(--bg))" },
  { key: "error", label: "Erreurs", color: "var(--text-muted)" },
];

// Étapes exécutées localement par le pare-feu. La couche IA et le LLM cible ont des
// ordres de grandeur 1000 fois plus grands : ils sont affichés à part, sinon ces
// barres seraient invisibles.
const LOCAL_STAGES = [
  { key: "rules", label: "Couche 1 · règles" },
  { key: "pii", label: "Détection PII" },
  { key: "audit", label: "Journal d'audit" },
];

const fmtMs = (v) => (v == null ? "n/d" : v >= 100 ? `${Math.round(v)} ms` : `${v.toFixed(v < 10 ? 2 : 1)} ms`);
const pct = (n, d) => (d ? Math.round((100 * n) / d) : 0);
const hhmm = (ts) => {
  const d = new Date(ts * 1000);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
};

function useJson(path, refreshMs) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(false);
  const load = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}${path}`);
      if (!res.ok) throw new Error();
      setData(await res.json());
      setError(false);
    } catch {
      setError(true);
    }
  }, [path]);
  useEffect(() => {
    load();
    if (!refreshMs) return undefined;
    const id = setInterval(load, refreshMs);
    return () => clearInterval(id);
  }, [load, refreshMs]);
  return { data, error, reload: load };
}

/* ------------------------------------------------------------------ Performances */

function Kpi({ label, value, hint, tone }) {
  return (
    <div className={`kpi ${tone ? `kpi--${tone}` : ""}`}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value}</div>
      {hint && <div className="kpi-hint">{hint}</div>}
    </div>
  );
}

function StageBars({ stages }) {
  const rows = LOCAL_STAGES.map((s) => ({ ...s, ...(stages?.[s.key] || {}) })).filter((r) => r.count);
  if (!rows.length) return <div className="empty-state">Aucune mesure pour l'instant.</div>;
  const max = Math.max(...rows.map((r) => r.p95 || 0), 0.01);
  return (
    <div className="stage-bars" role="table" aria-label="Latence par étape locale">
      <div className="stage-legend">
        <span><i className="swatch swatch--mean" /> moyenne</span>
        <span><i className="swatch swatch--p95" /> 95e centile</span>
      </div>
      {rows.map((r) => (
        <div className="stage-row" role="row" key={r.key}>
          <span className="stage-name">{r.label}</span>
          <div className="stage-track">
            <div className="stage-bar stage-bar--p95" style={{ width: `${(100 * r.p95) / max}%` }} />
            <div className="stage-bar stage-bar--mean" style={{ width: `${(100 * r.mean) / max}%` }} />
          </div>
          <span className="stage-val mono">
            {fmtMs(r.mean)} <span className="muted">/ {fmtMs(r.p95)}</span>
          </span>
        </div>
      ))}
    </div>
  );
}

function Performance() {
  const { data, error } = useJson("/v1/admin/metrics/performance", REFRESH_MS);
  if (error && !data) return <div className="banner-error">Mesures indisponibles.</div>;
  const fw = data?.firewall_without_classifier;
  const ia = data?.stages?.classifier;
  const llm = data?.stages?.llm;
  const target = data?.target_ms ?? 50;
  const met = data?.meets_target;

  return (
    <section className="analysis-panel">
      <header className="analysis-panel__head">
        <div>
          <h2>Performances</h2>
          <p className="muted">
            Temps ajouté par le pare-feu, mesuré requête par requête sur les {data?.window ?? 0} dernières.
            Le temps du modèle cible est exclu.
          </p>
        </div>
        {data && fw?.count > 0 && (
          <span className={`target-badge ${met ? "target-badge--ok" : "target-badge--ko"}`}>
            {met ? "Cible respectée" : "Cible dépassée"} : P95 {fmtMs(fw.p95)} pour {target} ms
          </span>
        )}
      </header>

      <div className="kpi-grid">
        <Kpi label="Moyenne" value={fmtMs(fw?.mean)} />
        <Kpi label="P50" value={fmtMs(fw?.p50)} />
        <Kpi label="P95" value={fmtMs(fw?.p95)} tone={fw?.count ? (met ? "ok" : "ko") : undefined} />
        <Kpi label="P99" value={fmtMs(fw?.p99)} />
      </div>
      <p className="kpi-caption muted">
        Couche 1, détection PII et journal. La couche IA est mesurée séparément ci-dessous.
      </p>

      <div className="perf-split">
        <div>
          <h3>Latence par étape locale</h3>
          <StageBars stages={data?.stages} />
        </div>
        <div className="side-kpis">
          <Kpi
            label="Couche 2 · classifieur IA"
            value={ia?.count ? fmtMs(ia.mean) : "inactive"}
            hint={ia?.count ? `P95 ${fmtMs(ia.p95)} sur ${ia.count} appels` : "aucune clé API configurée"}
            tone="ia"
          />
          <Kpi
            label="Modèle cible (exclu du KPI)"
            value={!llm?.count ? "n/d" : llm.mean < 1 ? "simulé" : fmtMs(llm.mean)}
            hint={
              !llm?.count
                ? undefined
                : llm.mean < 1
                  ? "aucune clé API : réponses simulées"
                  : `P95 ${fmtMs(llm.p95)} sur ${llm.count} réponses`
            }
          />
        </div>
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ Tableau de bord */

function Timeline({ timeline }) {
  const W = 1000;
  const H = 240;
  const pad = { l: 32, r: 8, t: 8, b: 24 };
  const n = timeline.length;
  const totals = timeline.map((b) => DECISIONS.reduce((s, d) => s + b[d.key], 0));
  const max = Math.max(1, ...totals);
  const step = Math.max(1, Math.ceil(max / 4));
  const yMax = step * 4;
  const bw = (W - pad.l - pad.r) / n;
  const y = (v) => pad.t + (H - pad.t - pad.b) * (1 - v / yMax);
  const labelEvery = Math.ceil(n / 8);

  return (
    <svg className="timeline" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Requêtes par tranche horaire">
      {[0, 1, 2, 3, 4].map((i) => (
        <g key={i}>
          <line x1={pad.l} x2={W - pad.r} y1={y(i * step)} y2={y(i * step)} className="grid-line" />
          <text x={pad.l - 6} y={y(i * step) + 4} textAnchor="end" className="axis-text">{i * step}</text>
        </g>
      ))}
      {timeline.map((b, i) => {
        let acc = 0;
        return (
          <g key={b.start}>
            <title>{`${hhmm(b.start)} : ${totals[i]} requête(s)`}</title>
            {DECISIONS.map((d) => {
              const v = b[d.key];
              if (!v) return null;
              const y0 = y(acc + v);
              const h = y(acc) - y0;
              acc += v;
              return <rect key={d.key} x={pad.l + i * bw + 1} y={y0} width={Math.max(bw - 2, 1)} height={h} fill={d.color} rx="1.5" />;
            })}
            {i % labelEvery === 0 && (
              <text x={pad.l + i * bw + bw / 2} y={H - 6} textAnchor="middle" className="axis-text">{hhmm(b.start)}</text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

function DecisionBreakdown({ byDecision, total }) {
  return (
    <div className="breakdown">
      <div className="breakdown-bar" aria-hidden="true">
        {DECISIONS.map((d) =>
          byDecision[d.key] ? (
            <span key={d.key} style={{ width: `${(100 * byDecision[d.key]) / total}%`, background: d.color }} />
          ) : null,
        )}
      </div>
      <ul className="breakdown-legend">
        {DECISIONS.map((d) => (
          <li key={d.key}>
            <i className="swatch" style={{ background: d.color }} />
            <span>{d.label}</span>
            <span className="mono">{byDecision[d.key]}</span>
            <span className="muted mono">{pct(byDecision[d.key], total)} %</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Overview() {
  const { data, error } = useJson("/v1/admin/metrics/summary?hours=24&bucket_minutes=60", REFRESH_MS);
  if (error && !data) return <div className="banner-error">Statistiques indisponibles.</div>;
  return (
    <section className="analysis-panel">
      <header className="analysis-panel__head">
        <div>
          <h2>Tableau de bord</h2>
          <p className="muted">Décisions du pare-feu sur les dernières 24 heures, par heure.</p>
        </div>
        <span className="mono muted">{data?.total ?? 0} requêtes</span>
      </header>
      {data && data.total > 0 ? (
        <>
          <Timeline timeline={data.timeline} />
          <DecisionBreakdown byDecision={data.by_decision} total={data.total} />
        </>
      ) : (
        <div className="empty-state">Aucune requête sur les dernières 24 heures.</div>
      )}
    </section>
  );
}

/* ------------------------------------------------------------------ Red Team */

function Rate({ detected, total }) {
  return (
    <span className="rate">
      <span className="rate-bar"><span style={{ width: `${pct(detected, total)}%` }} /></span>
      <span className="mono rate-count">{detected}/{total}</span>
      <span className="mono muted rate-pct">{pct(detected, total)} %</span>
    </span>
  );
}

function RedTeam({ classifierOn }) {
  const last = useJson("/v1/admin/redteam/last", 0);
  const [result, setResult] = useState(null);
  const [running, setRunning] = useState(null);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState("holdout_b");
  const shown = result || last.data;

  async function launch(layer2) {
    setRunning(layer2 ? "layer2" : "layer1");
    setError(null);
    try {
      const res = await fetch(`${API_URL}/v1/admin/redteam/run?layer2=${layer2}`, { method: "POST" });
      const body = await res.json();
      if (!res.ok) throw new Error(body.detail || "Échec de la campagne");
      setResult(body);
    } catch (err) {
      setError(err.message);
    } finally {
      setRunning(null);
    }
  }

  const corpus = shown?.corpora?.find((c) => c.key === selected);

  return (
    <section className="analysis-panel">
      <header className="analysis-panel__head">
        <div>
          <h2>Laboratoire Red Team</h2>
          <p className="muted">
            Rejoue les corpus d'attaques du projet contre la couche 1 seule, puis contre les deux couches.
          </p>
        </div>
        <div className="redteam-actions">
          <button type="button" className="preset-btn" disabled={!!running} onClick={() => launch(false)}>
            {running === "layer1" ? "Campagne en cours…" : "Lancer · couche 1"}
          </button>
          <button
            type="button"
            className="send-btn send-btn--small"
            disabled={!!running || !classifierOn}
            onClick={() => launch(true)}
            title={classifierOn ? "Environ 150 appels au classifieur IA (payants)" : "Classifieur IA inactif : aucune clé API configurée"}
          >
            {running === "layer2" ? "Classifieur en cours (30 s environ)…" : "Lancer · couches 1 + 2"}
          </button>
        </div>
      </header>

      {error && <div className="banner-error">{error}</div>}

      {!shown ? (
        <div className="empty-state">Aucune campagne lancée depuis le démarrage du serveur.</div>
      ) : (
        <>
          <p className="muted small">
            Dernière campagne à {hhmm(shown.ran_at)}, en {Math.round(shown.duration_ms)} ms
            {shown.layer2_used ? `, classifieur ${shown.classifier.classifier_model}` : ", couche 1 seule"}
            {shown.cached ? " (résultat récent réutilisé : une campagne IA par minute au plus)" : ""}.
          </p>
          <div className="redteam-table" role="table">
            <div className="rt-row rt-row--head" role="row">
              <span>corpus</span>
              <span>couche 1 seule</span>
              <span>couches 1 + 2</span>
              <span>faux positifs (1 / 1+2)</span>
            </div>
            {shown.corpora.map((c) => (
              <button
                type="button"
                className={`rt-row ${selected === c.key ? "rt-row--active" : ""}`}
                role="row"
                key={c.key}
                onClick={() => setSelected(c.key)}
              >
                <span>
                  <strong>{c.label}</strong>
                  <span className="muted small rt-note">{c.note}</span>
                </span>
                <Rate detected={c.layer1.detected} total={c.attacks} />
                {c.combined ? <Rate detected={c.combined.detected} total={c.attacks} /> : <span className="muted">non mesuré</span>}
                <span className="mono">
                  {c.layer1.false_positives}/{c.benign}
                  {c.combined ? ` / ${c.combined.false_positives}/${c.benign}` : ""}
                </span>
              </button>
            ))}
          </div>

          {corpus && (
            <div className="rt-detail">
              <div>
                <h3>Par catégorie · {corpus.label}</h3>
                <div className="rt-cats">
                  {corpus.per_category.map((cat) => (
                    <div className="rt-cat" key={cat.category}>
                      <span className="mono">{cat.category}</span>
                      <Rate detected={corpus.combined ? cat.combined : cat.layer1} total={cat.total} />
                    </div>
                  ))}
                </div>
                <p className="muted small">
                  Couche 1 : {fmtMs(corpus.latency.rules.p50)} médiane, {fmtMs(corpus.latency.rules.p95)} au P95.
                  {corpus.latency.classifier ? ` Couche IA : ${fmtMs(corpus.latency.classifier.p50)} médiane.` : ""}
                </p>
              </div>
              <div>
                <h3>Attaques non détectées ({corpus.attacks - (corpus.combined || corpus.layer1).detected})</h3>
                {corpus.missed.length ? (
                  <ul className="rt-missed">
                    {corpus.missed.map((m, i) => (
                      <li key={i}>
                        <span className="mono muted">{m.category}</span> {m.text}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <div className="empty-state">Aucune sur ce corpus.</div>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </section>
  );
}

export default function Analysis({ classifierOn }) {
  return (
    <div className="analysis">
      <Performance />
      <Overview />
      <RedTeam classifierOn={classifierOn} />
    </div>
  );
}
