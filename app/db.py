"""Connexion à la base de données et modèles SQLAlchemy.

Fonctionne aussi bien avec PostgreSQL (production, via docker-compose) qu'avec
SQLite (développement local et tests, aucune dépendance externe à installer).
"""
from datetime import datetime

from sqlalchemy import Column, DateTime, Float, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import DATABASE_URL

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class AuditLogEntry(Base):
    """Une ligne = un événement du firewall, chaînée par hachage (voir app/audit/logger.py)."""

    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, default=lambda: datetime.utcnow().timestamp())
    request_id = Column(String(64), nullable=False, index=True)
    event_type = Column(String(32), nullable=False, index=True)  # allowed | sanitized | blocked_pii | blocked_injection | error
    detail = Column(String(1000), nullable=False)
    prev_hash = Column(String(64), nullable=False)
    entry_hash = Column(String(64), nullable=False)


class RequestMetric(Base):
    """Latences mesurées pour une requête, étape par étape (voir app/metrics.py).

    Table séparée du journal d'audit, volontairement : les latences sont des
    données opérationnelles, pas des preuves de conformité. Les garder hors de la
    chaîne de hachage évite de modifier le format des entrées d'audit existantes.
    Une colonne vaut NULL quand l'étape n'a pas été exécutée (ex. la couche IA
    ne tourne pas si les règles ont déjà bloqué, ou si aucune clé n'est configurée).
    """

    __tablename__ = "request_metrics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, index=True)
    request_id = Column(String(64), nullable=False, index=True)
    event_type = Column(String(32), nullable=False, index=True)
    rules_ms = Column(Float, nullable=True)        # couche 1 : règles pondérées
    classifier_ms = Column(Float, nullable=True)   # couche 2 : classifieur IA
    pii_ms = Column(Float, nullable=True)          # détection + masquage PII
    audit_ms = Column(Float, nullable=True)        # écriture du journal chaîné
    llm_ms = Column(Float, nullable=True)          # LLM cible (exclu du KPI pare-feu)
    firewall_ms = Column(Float, nullable=False)    # total - llm_ms : ce qu'ajoute le pare-feu
    total_ms = Column(Float, nullable=False)       # temps de bout en bout


def init_db():
    Base.metadata.create_all(bind=engine)


def get_session():
    return SessionLocal()
