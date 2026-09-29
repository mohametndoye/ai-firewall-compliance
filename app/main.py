"""AI Firewall & Compliance — point d'entrée du proxy.

Flux (voir cahier des charges §5) :
  1. Réception de la requête
  2. Détection PII sur le texte entrant -> assainissement ou blocage
  3. Détection prompt injection/jailbreak -> blocage si score élevé
  4. Transmission au LLM en aval (si autorisé)
  5. Journalisation de l'événement (toujours, quelle que soit l'issue)
"""
import time
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from app.audit.logger import get_recent_events, get_stats, log_event
from app.config import FAILURE_POLICY, PROVIDER_API_KEYS, PROVIDER_BASE_URLS
from app.db import init_db
from app.detectors import injection, llm_classifier, pii


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="AI Firewall & Compliance", version="0.2.0", lifespan=lifespan)

# Le tableau de bord React (dev server sur un autre port, ex. 5173) doit pouvoir
# appeler cette API depuis le navigateur.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ProxyRequest(BaseModel):
    provider: str  # "openai" | "anthropic"
    model: str
    prompt: str


class ProxyResponse(BaseModel):
    request_id: str
    status: str  # "allowed" | "sanitized" | "blocked_injection" | "blocked_injection_ia"
    detail: str
    added_latency_ms: float
    completion: str | None = None
    layer: str | None = None  # "regles" | "ia" — quelle couche a rendu le verdict de blocage


@app.get("/")
def root():
    """Racine de l'API : redirige vers la documentation interactive plutôt que
    de retourner un 404 déroutant quand on visite juste http://localhost:8000/."""
    return RedirectResponse(url="/docs")


@app.get("/health")
def health():
    return {"status": "ok", **pii.presidio_status(), **llm_classifier.status()}


@app.get("/v1/admin/stats")
def admin_stats():
    return get_stats()


@app.get("/v1/admin/events")
def admin_events(limit: int = 50):
    return get_recent_events(limit=limit)


@app.post("/v1/proxy/chat", response_model=ProxyResponse)
async def proxy_chat(req: ProxyRequest):
    request_id = str(uuid.uuid4())
    start = time.perf_counter()

    if req.provider not in PROVIDER_BASE_URLS:
        raise HTTPException(status_code=400, detail=f"Fournisseur non supporté : {req.provider}")

    try:
        # Étape 1 — détection d'injection, 1re couche : règles pondérées (rapide,
        # gratuite, hors ligne). On bloque avant même de regarder le PII : une
        # requête malveillante n'a pas besoin d'être assainie, elle doit être stoppée.
        injection_result = injection.scan(req.prompt)
        if injection_result.is_blocked:
            log_event(request_id, "blocked_injection", "; ".join(injection_result.matched_rules))
            elapsed_ms = (time.perf_counter() - start) * 1000
            return ProxyResponse(
                request_id=request_id,
                status="blocked_injection",
                detail=f"Requête bloquée par les règles (score de risque {injection_result.score})",
                added_latency_ms=round(elapsed_ms, 2),
                layer="regles",
            )

        # Étape 1bis — 2e couche, optionnelle : classifieur LLM jugeant l'intention.
        # Ne s'exécute que si une clé API est configurée (voir app/detectors/llm_classifier.py) ;
        # conçue pour rattraper les reformulations que les règles ne peuvent pas anticiper.
        classifier_result = await llm_classifier.evaluate(req.prompt)
        if classifier_result.is_blocking:
            log_event(
                request_id,
                "blocked_injection_ia",
                f"Classifieur IA ({classifier_result.provider}/{classifier_result.model}), "
                f"confiance {classifier_result.confidence}% : {classifier_result.reason}",
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            return ProxyResponse(
                request_id=request_id,
                status="blocked_injection_ia",
                detail=f"Requête bloquée par le classifieur IA (confiance {classifier_result.confidence}%) : {classifier_result.reason}",
                added_latency_ms=round(elapsed_ms, 2),
                layer="ia",
            )

        # Étape 2 — détection et assainissement des données sensibles (PII)
        pii_result = pii.scan_and_sanitize(req.prompt)
        outgoing_prompt = pii_result.sanitized_text if pii_result.has_pii else req.prompt

        # Étape 3 — transmission au LLM en aval
        completion = await _forward_to_provider(req.provider, req.model, outgoing_prompt)

        event_type = "sanitized" if pii_result.has_pii else "allowed"
        detail = f"{len(pii_result.findings)} donnée(s) sensible(s) masquée(s)" if pii_result.has_pii else "requête conforme"
        log_event(request_id, event_type, detail)

        elapsed_ms = (time.perf_counter() - start) * 1000
        return ProxyResponse(
            request_id=request_id,
            status=event_type,
            detail=detail,
            added_latency_ms=round(elapsed_ms, 2),
            completion=completion,
        )

    except Exception as exc:
        log_event(request_id, "error", str(exc))
        if FAILURE_POLICY == "fail_open":
            raise
        raise HTTPException(status_code=503, detail="AI Firewall indisponible (politique fail_closed)")


async def _forward_to_provider(provider: str, model: str, prompt: str) -> str:
    """Transmet le prompt assaini au fournisseur de LLM réel.

    En développement (sans clé API valide), cette fonction retourne une réponse
    simulée pour permettre de tester tout le pipeline sans dépendance externe.
    """
    api_key = PROVIDER_API_KEYS.get(provider, "")
    if not api_key:
        return f"[réponse simulée — aucune clé API {provider} configurée] Écho: {prompt[:120]}"

    base_url = PROVIDER_BASE_URLS[provider]
    async with httpx.AsyncClient(timeout=10.0) as client:
        if provider == "openai":
            resp = await client.post(
                f"{base_url}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={"model": model, "messages": [{"role": "user", "content": prompt}]},
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        else:  # anthropic
            resp = await client.post(
                f"{base_url}/messages",
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"},
                json={"model": model, "max_tokens": 1000, "messages": [{"role": "user", "content": prompt}]},
            )
            resp.raise_for_status()
            return resp.json()["content"][0]["text"]
