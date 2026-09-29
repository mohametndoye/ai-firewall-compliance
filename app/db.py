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


def init_db():
    Base.metadata.create_all(bind=engine)


def get_session():
    return SessionLocal()
