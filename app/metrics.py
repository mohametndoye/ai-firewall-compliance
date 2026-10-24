"""Mesure des performances du pare-feu, étape par étape.

Pourquoi ce module : jusqu'ici, `added_latency_ms` mesurait le temps total de la
requête, appel au LLM cible compris. Ce chiffre ne permettait pas de vérifier
l'exigence du cahier des charges (§4 : moins de 50 ms ajoutées par la 1re couche),
puisqu'un appel au modèle prend à lui seul une à plusieurs secondes.

Chaque requête est maintenant découpée en étapes chronométrées séparément :

    règles (couche 1) -> classifieur IA (couche 2) -> PII -> LLM cible -> audit

Le temps du LLM cible est mesuré mais EXCLU du KPI « latence du pare-feu » : ce
n'est pas le pare-feu qui le consomme. La couche IA, elle, est bien du temps
ajouté par le pare-feu, mais elle est rapportée à part pour que la cible de
50 ms s'applique à la couche 1, comme le prévoit le cahier des charges.
"""
import math
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

from app.config import MAX_ADDED_LATENCY_MS
from app.db import AuditLogEntry, RequestMetric, get_session

# Étapes chronométrées : clé interne -> colonne de la table request_metrics
STAGES = {
    "rules": "rules_ms",
    "classifier": "classifier_ms",
    "pii": "pii_ms",
    "audit": "audit_ms",
    "llm": "llm_ms",
}


@dataclass
class Trace:
    """Chronomètre d'une requête. Usage :

        trace = Trace()
        with trace.stage("rules"):
            injection.scan(prompt)
        trace.finish()  # fige le total
    """

    start: float = field(default_factory=time.perf_counter)
    stages: dict = field(default_factory=dict)
    total_ms: float | None = None

    @contextmanager
    def stage(self, name: str):
        t0 = time.perf_counter()
        try:
            yield
        finally:
            # += : une étape peut être chronométrée en plusieurs morceaux
            self.stages[name] = self.stages.get(name, 0.0) + (time.perf_counter() - t0) * 1000

    def finish(self) -> None:
        self.total_ms = (time.perf_counter() - self.start) * 1000

    @property
    def elapsed_ms(self) -> float:
        return self.total_ms if self.total_ms is not None else (time.perf_counter() - self.start) * 1000

    @property
    def llm_ms(self) -> float:
        return self.stages.get("llm", 0.0)

    @property
    def firewall_ms(self) -> float:
        """Temps ajouté par le pare-feu : tout, sauf l'attente du LLM cible."""
        return max(self.elapsed_ms - self.llm_ms, 0.0)

    def breakdown(self) -> dict:
        """Détail renvoyé au client dans la réponse du proxy (arrondi pour l'affichage)."""
        out = {name: round(ms, 2) for name, ms in self.stages.items()}
        out["firewall"] = round(self.firewall_ms, 2)
        out["total"] = round(self.elapsed_ms, 2)
        return out


def record(request_id: str, event_type: str, trace: Trace) -> None:
    """Enregistre les latences d'une requête. Ne lève jamais : une panne de la
    mesure ne doit pas faire échouer une requête utilisateur."""
    session = get_session()
    try:
        session.add(
            RequestMetric(
                timestamp=time.time(),
                request_id=request_id,
                event_type=event_type,
                firewall_ms=trace.firewall_ms,
                total_ms=trace.elapsed_ms,
                **{col: trace.stages.get(name) for name, col in STAGES.items()},
            )
        )
        session.commit()
    except Exception:  # noqa: BLE001
        session.rollback()
    finally:
        session.close()


# ---------------------------------------------------------------- statistiques


def percentile(values: list[float], p: float) -> float:
    """Centile par interpolation linéaire (même définition que numpy par défaut)."""
    if not values:
        return 0.0
    v = sorted(values)
    k = (len(v) - 1) * p / 100
    lo, hi = math.floor(k), math.ceil(k)
    return v[lo] + (v[hi] - v[lo]) * (k - lo)


def describe(values: list[float]) -> dict:
    if not values:
        return {"count": 0, "mean": None, "p50": None, "p95": None, "p99": None, "max": None}
    return {
        "count": len(values),
        "mean": round(sum(values) / len(values), 2),
        "p50": round(percentile(values, 50), 2),
        "p95": round(percentile(values, 95), 2),
        "p99": round(percentile(values, 99), 2),
        "max": round(max(values), 2),
    }


def performance(limit: int = 1000) -> dict:
    """Statistiques de latence sur les `limit` dernières requêtes."""
    session = get_session()
    try:
        rows = session.query(RequestMetric).order_by(RequestMetric.id.desc()).limit(limit).all()
    finally:
        session.close()

    def col(name: str) -> list[float]:
        return [getattr(r, name) for r in rows if getattr(r, name) is not None]

    # Pare-feu sans la couche IA : c'est ce chiffre que vise l'exigence des 50 ms.
    without_ia = [r.firewall_ms - (r.classifier_ms or 0.0) for r in rows]
    without_ia_stats = describe(without_ia)

    return {
        "window": len(rows),
        "target_ms": MAX_ADDED_LATENCY_MS,
        "firewall": describe(col("firewall_ms")),
        "firewall_without_classifier": without_ia_stats,
        "meets_target": without_ia_stats["p95"] is not None and without_ia_stats["p95"] < MAX_ADDED_LATENCY_MS,
        "stages": {name: describe(col(c)) for name, c in STAGES.items()},
    }


DECISIONS = ["allowed", "sanitized", "blocked_injection", "blocked_injection_ia", "blocked_pii", "error"]


def summary(hours: int = 24, bucket_minutes: int = 60) -> dict:
    """Répartition des décisions et courbe des requêtes dans le temps, calculées
    depuis le journal d'audit (source de vérité, y compris avant ce module)."""
    hours = max(1, min(hours, 24 * 30))
    bucket_s = max(1, bucket_minutes) * 60
    now = time.time()
    since = now - hours * 3600

    session = get_session()
    try:
        rows = (
            session.query(AuditLogEntry.timestamp, AuditLogEntry.event_type)
            .filter(AuditLogEntry.timestamp >= since)
            .all()
        )
    finally:
        session.close()

    first_bucket = int(since // bucket_s) * bucket_s
    n_buckets = int((now - first_bucket) // bucket_s) + 1
    timeline = [{"start": first_bucket + i * bucket_s, **{d: 0 for d in DECISIONS}} for i in range(n_buckets)]
    totals = {d: 0 for d in DECISIONS}

    for ts, event_type in rows:
        key = event_type if event_type in totals else "error"
        totals[key] += 1
        idx = min(int((ts - first_bucket) // bucket_s), n_buckets - 1)
        timeline[idx][key] += 1

    return {
        "hours": hours,
        "bucket_minutes": bucket_s // 60,
        "total": sum(totals.values()),
        "by_decision": totals,
        "timeline": timeline,
    }
