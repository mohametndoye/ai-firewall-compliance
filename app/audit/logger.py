"""Journal d'audit infalsifiable, conforme à l'esprit de l'art. 12 de l'EU AI Act
(enregistrement automatique, traçable, sur tout le cycle de vie de chaque requête).

Chaque entrée contient le hash de l'entrée précédente (chaînage façon blockchain
simplifiée) : toute modification ou suppression rétroactive d'une entrée invalide
la chaîne à partir de ce point, ce qui rend la falsification détectable.

Persisté en base de données (PostgreSQL en production, SQLite en développement —
voir app/db.py) plutôt qu'en fichier plat, pour permettre les requêtes du tableau
de bord (statistiques, filtrage par type d'événement, etc.).
"""
import hashlib
import json
import time
from dataclasses import dataclass

from sqlalchemy import func

from app.db import AuditLogEntry, get_session

GENESIS_HASH = "0" * 64


@dataclass
class AuditEntry:
    timestamp: float
    request_id: str
    event_type: str  # "allowed" | "blocked_pii" | "blocked_injection" | "sanitized" | "error"
    detail: str
    prev_hash: str
    entry_hash: str = ""


def _compute_hash(entry: AuditEntry) -> str:
    payload = json.dumps(
        {
            "timestamp": entry.timestamp,
            "request_id": entry.request_id,
            "event_type": entry.event_type,
            "detail": entry.detail,
            "prev_hash": entry.prev_hash,
        },
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def log_event(request_id: str, event_type: str, detail: str) -> AuditEntry:
    session = get_session()
    try:
        last = session.query(AuditLogEntry).order_by(AuditLogEntry.id.desc()).first()
        prev_hash = last.entry_hash if last else GENESIS_HASH

        entry = AuditEntry(timestamp=time.time(), request_id=request_id, event_type=event_type, detail=detail, prev_hash=prev_hash)
        entry.entry_hash = _compute_hash(entry)

        db_entry = AuditLogEntry(
            timestamp=entry.timestamp,
            request_id=entry.request_id,
            event_type=entry.event_type,
            detail=entry.detail,
            prev_hash=entry.prev_hash,
            entry_hash=entry.entry_hash,
        )
        session.add(db_entry)
        session.commit()
        return entry
    finally:
        session.close()


def verify_chain() -> bool:
    """Vérifie l'intégrité de toute la chaîne de logs. Utilisé par le tableau de
    bord pour afficher un indicateur de conformité (audit non falsifié)."""
    session = get_session()
    try:
        rows = session.query(AuditLogEntry).order_by(AuditLogEntry.id.asc()).all()
        prev_hash = GENESIS_HASH
        for row in rows:
            entry = AuditEntry(
                timestamp=row.timestamp, request_id=row.request_id, event_type=row.event_type, detail=row.detail, prev_hash=row.prev_hash
            )
            expected_hash = _compute_hash(entry)
            if expected_hash != row.entry_hash or row.prev_hash != prev_hash:
                return False
            prev_hash = row.entry_hash
        return True
    finally:
        session.close()


def get_stats() -> dict:
    """Statistiques agrégées pour le tableau de bord."""
    session = get_session()
    try:
        rows = session.query(AuditLogEntry.event_type, func.count(AuditLogEntry.id)).group_by(AuditLogEntry.event_type).all()
        by_type = {event_type: count for event_type, count in rows}
        total = sum(by_type.values())
        return {
            "total_requests": total,
            "allowed": by_type.get("allowed", 0),
            "sanitized": by_type.get("sanitized", 0),
            "blocked_pii": by_type.get("blocked_pii", 0),
            "blocked_injection": by_type.get("blocked_injection", 0),
            "errors": by_type.get("error", 0),
            "chain_valid": verify_chain(),
        }
    finally:
        session.close()


def get_recent_events(limit: int = 50) -> list:
    session = get_session()
    try:
        rows = session.query(AuditLogEntry).order_by(AuditLogEntry.id.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "timestamp": r.timestamp,
                "request_id": r.request_id,
                "event_type": r.event_type,
                "detail": r.detail,
            }
            for r in rows
        ]
    finally:
        session.close()
