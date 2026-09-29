"""Détection des données personnelles ou sensibles (PII).

Deux couches de détection, combinées :

1. Expressions régulières pour les catégories à format fixe (courriel, téléphone,
   carte de crédit, NAS/SSN) — rapides, déterministes, sans dépendance externe.
2. Microsoft Presidio (NER via spaCy) pour les catégories contextuelles que les
   regex ne peuvent pas couvrir, notamment les noms de personnes et les adresses.

Si Presidio ou son modèle de langue ne sont pas installés (ex. environnement de
démonstration minimal), le module se replie silencieusement sur les regex seules
plutôt que de faire planter le proxy — cohérent avec la politique fail_closed du
firewall : une couche de détection en moins ne doit pas mettre tout le service à terre.
"""
import re
from dataclasses import dataclass, field

PII_PATTERNS = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "phone": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "sin_ssn": re.compile(r"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b"),
}

# Catégories Presidio qu'on choisit de retenir (on exclut LOCATION : dans un contexte
# de requêtes à un LLM, mentionner un lieu — "la météo à Gatineau" — n'est presque
# jamais une donnée personnelle sensible, et c'est la source de faux positifs la plus
# fréquente observée pendant nos tests).
PRESIDIO_CATEGORIES_KEPT = {"PER", "PERSON", "CREDIT_CARD", "EMAIL_ADDRESS", "PHONE_NUMBER"}
PRESIDIO_MIN_SCORE = 0.5

_presidio_analyzer = None
_presidio_available = False


def _try_load_presidio():
    """Charge Presidio une seule fois (coûteux) et mémorise s'il est disponible.

    Modèle français par défaut : le projet et ses utilisateurs cibles sont
    francophones (voir cahier des charges). Un modèle anglais appliqué à du texte
    français produit des faux positifs (ex. « vas-tu » détecté comme un nom propre).
    """
    global _presidio_analyzer, _presidio_available
    if _presidio_analyzer is not None or _presidio_available:
        return
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "fr", "model_name": "fr_core_news_sm"}],
        }
        provider = NlpEngineProvider(nlp_configuration=config)
        nlp_engine = provider.create_engine()
        _presidio_analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["fr"])
        _presidio_available = True
    except Exception:
        # Modèle non installé, dépendance manquante, etc. -> on continue avec les regex seules.
        _presidio_analyzer = None
        _presidio_available = False


@dataclass
class PiiFinding:
    category: str
    match: str
    start: int
    end: int
    source: str = "regex"  # "regex" | "presidio"


@dataclass
class PiiScanResult:
    findings: list = field(default_factory=list)
    sanitized_text: str = ""

    @property
    def has_pii(self) -> bool:
        return len(self.findings) > 0


def scan_and_sanitize(text: str) -> PiiScanResult:
    """Analyse un texte avec les regex + Presidio (si disponible), retourne les
    occurrences trouvées et une version assainie où chaque occurrence est
    remplacée par un jeton [REDACTED:<catégorie>]."""
    findings: list[PiiFinding] = []

    for category, pattern in PII_PATTERNS.items():
        for m in pattern.finditer(text):
            findings.append(PiiFinding(category=category, match=m.group(), start=m.start(), end=m.end(), source="regex"))

    _try_load_presidio()
    if _presidio_available:
        try:
            results = _presidio_analyzer.analyze(text=text, language="fr")
            for r in results:
                if r.entity_type not in PRESIDIO_CATEGORIES_KEPT or r.score < PRESIDIO_MIN_SCORE:
                    continue
                # Évite les doublons avec ce que les regex ont déjà trouvé au même endroit
                overlap = any(f.start <= r.start < f.end or r.start <= f.start < r.end for f in findings)
                if not overlap:
                    findings.append(
                        PiiFinding(category=r.entity_type.lower(), match=text[r.start : r.end], start=r.start, end=r.end, source="presidio")
                    )
        except Exception:
            pass  # dégradation silencieuse : les regex ont déjà tourné, on garde leurs résultats

    # Remplacement en partant de la fin pour ne pas décaler les index déjà calculés
    sanitized = text
    for finding in sorted(findings, key=lambda f: f.start, reverse=True):
        token = f"[REDACTED:{finding.category}]"
        sanitized = sanitized[: finding.start] + token + sanitized[finding.end :]

    return PiiScanResult(findings=findings, sanitized_text=sanitized)


def presidio_status() -> dict:
    """Utilisé par /health pour indiquer si la détection contextuelle est active."""
    _try_load_presidio()
    return {"presidio_available": _presidio_available}

