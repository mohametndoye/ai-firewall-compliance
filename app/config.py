"""Configuration centrale du AI Firewall.

Les valeurs par défaut conviennent au développement local. En production,
toutes ces valeurs devraient venir de variables d'environnement (.env).
"""
import os

from dotenv import load_dotenv

# Charge automatiquement un fichier .env s'il existe (développement local) ;
# n'écrase jamais des variables déjà définies dans l'environnement (Docker,
# Render, etc. restent prioritaires).
load_dotenv()

# Latence maximale tolérée ajoutée par le proxy (exigence RNF, cahier des charges §4)
MAX_ADDED_LATENCY_MS = 50

# Politique en cas d'erreur interne du firewall : "fail_open" laisse passer la requête,
# "fail_closed" la bloque. Pour un prototype académique, fail_closed est plus prudent.
FAILURE_POLICY = os.getenv("AI_FIREWALL_FAILURE_POLICY", "fail_closed")

# Fournisseurs de LLM supportés et leur URL de base réelle
PROVIDER_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
}

# Clés API des fournisseurs en aval (à fournir par l'entreprise cliente du firewall)
PROVIDER_API_KEYS = {
    "openai": os.getenv("OPENAI_API_KEY", ""),
    "anthropic": os.getenv("ANTHROPIC_API_KEY", ""),
}

# Base de données (PostgreSQL en production, SQLite en développement/tests si
# DATABASE_URL n'est pas fournie — évite de dépendre d'un serveur Postgres pour
# lancer les tests localement, tout en gardant le même code SQLAlchemy pour les deux).
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./ai_firewall.db")

# --- Classifieur LLM (2e couche de détection d'injection, défense en profondeur) ---
#
# Le détecteur par règles (app/detectors/injection.py) est rapide et gratuit mais ne
# généralise pas aux reformulations inédites (voir docs/mesure_impartiale_holdout.md).
# Cette 2e couche, optionnelle, demande à un LLM de juger l'INTENTION du message
# plutôt que sa forme littérale. Elle ne s'active que si une clé API est configurée ;
# sans clé, le firewall fonctionne exactement comme avant (repli silencieux).
#
# Clé dédiée si on veut un fournisseur/compte différent de celui utilisé pour
# transmettre les requêtes en aval ; sinon on réutilise les clés déjà configurées.
CLASSIFIER_PROVIDER = os.getenv("AI_FIREWALL_CLASSIFIER_PROVIDER", "").strip().lower()
CLASSIFIER_API_KEY = os.getenv("AI_FIREWALL_CLASSIFIER_API_KEY", "").strip()

CLASSIFIER_MODELS = {
    "openai": os.getenv("AI_FIREWALL_CLASSIFIER_MODEL_OPENAI", "gpt-4o-mini"),
    "anthropic": os.getenv("AI_FIREWALL_CLASSIFIER_MODEL_ANTHROPIC", "claude-3-5-haiku-20241022"),
}

# Score de confiance (0-100) au-delà duquel le verdict du classifieur bloque la requête.
CLASSIFIER_SUSPICION_THRESHOLD = int(os.getenv("AI_FIREWALL_CLASSIFIER_THRESHOLD", "60"))
CLASSIFIER_TIMEOUT_S = float(os.getenv("AI_FIREWALL_CLASSIFIER_TIMEOUT_S", "6"))

# Presidio (NER via spaCy) charge un modèle de langue en mémoire (~200-300 Mo) en plus
# du reste de l'application — cela dépasse le quota RAM des plans gratuits de certains
# hébergeurs (ex. Render free : 512 Mo au total). Cette option permet de désactiver
# explicitement Presidio pour ne garder que la détection PII par regex (email,
# téléphone, carte de crédit, NAS/SSN), qui reste pleinement fonctionnelle et
# gratuite en ressources. Par défaut activé (comportement inchangé en local/Docker).
PRESIDIO_ENABLED = os.getenv("AI_FIREWALL_PRESIDIO_ENABLED", "true").strip().lower() not in ("false", "0", "no")
