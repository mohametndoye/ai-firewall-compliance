"""Campagne Red Team lancée depuis le tableau de bord.

Rejoue les corpus d'attaques déjà présents dans tests/ contre les deux couches
de détection et compare :
  - le taux de détection de la couche 1 seule (règles),
  - le taux de détection des couches 1 + 2 (règles puis classifieur IA),
  - les faux positifs de chaque configuration sur des messages légitimes.

C'est la « mesure fine du gain de la 2e couche » annoncée dans la présentation :
le lot B (hors échantillon, jamais utilisé pour écrire les règles) montre ce que
les règles ratent ; la couche 2 doit en rattraper l'essentiel sans bloquer les
messages légitimes.

Coût : la couche 1 est gratuite et instantanée. La couche 2 appelle l'API du
classifieur pour chaque message que les règles n'ont pas bloqué (environ 150
appels sur l'ensemble des corpus) ; elle est donc optionnelle et limitée à une
exécution par minute.
"""
import asyncio
import importlib
import sys
import time
from pathlib import Path

from app.detectors import injection, llm_classifier
from app.metrics import describe

TESTS_DIR = Path(__file__).resolve().parents[1] / "tests"

CORPORA = {
    "principal": {
        "module": "redteam_corpus",
        "label": "Corpus principal",
        "note": "A servi à écrire les règles : mesure les attaques connues.",
    },
    "holdout_a": {
        "module": "redteam_holdout_a",
        "label": "Lot hors échantillon A",
        "note": "Rédigé après un 1er durcissement, puis utilisé pour affiner les règles.",
    },
    "holdout_b": {
        "module": "redteam_holdout_b",
        "label": "Lot hors échantillon B",
        "note": "Jamais utilisé pour ajuster les règles : mesure la plus impartiale.",
    },
}

LAYER2_COOLDOWN_S = 60
CLASSIFIER_CONCURRENCY = 8

_last_result: dict | None = None
_last_layer2_run: float = 0.0
_lock = asyncio.Lock()


class RedTeamUnavailable(Exception):
    pass


def _load(key: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Charge un corpus depuis tests/ et normalise son format.
    (Le corpus principal stocke ses cas légitimes en tuples, les lots A et B en chaînes.)"""
    if not TESTS_DIR.is_dir():
        raise RedTeamUnavailable("Dossier tests/ absent du déploiement : corpus Red Team introuvables.")
    if str(TESTS_DIR) not in sys.path:
        sys.path.insert(0, str(TESTS_DIR))
    mod = importlib.import_module(CORPORA[key]["module"])
    attacks = [(cat, text) for cat, text in mod.ATTACKS]
    benign = [b[1] if isinstance(b, tuple) else b for b in mod.BENIGN]
    return attacks, benign


async def _classify_all(texts: list[str]) -> list:
    sem = asyncio.Semaphore(CLASSIFIER_CONCURRENCY)

    async def one(text: str):
        async with sem:
            return await llm_classifier.evaluate(text)

    return await asyncio.gather(*(one(t) for t in texts))


async def _run_corpus(key: str, use_layer2: bool) -> dict:
    attacks, benign = _load(key)

    rules_latencies: list[float] = []

    def scan(text: str):
        t0 = time.perf_counter()
        r = injection.scan(text)
        rules_latencies.append((time.perf_counter() - t0) * 1000)
        return r

    attack_l1 = [scan(text).is_blocked for _, text in attacks]
    benign_l1 = [scan(text).is_blocked for text in benign]

    # Couche 2 : seulement sur ce que la couche 1 a laissé passer, comme en production.
    attack_l2 = [None] * len(attacks)
    benign_l2 = [None] * len(benign)
    classifier_latencies: list[float] = []
    classifier_errors = 0
    if use_layer2:
        todo_a = [i for i, blocked in enumerate(attack_l1) if not blocked]
        todo_b = [i for i, blocked in enumerate(benign_l1) if not blocked]
        verdicts = await _classify_all([attacks[i][1] for i in todo_a] + [benign[i] for i in todo_b])
        for v in verdicts:
            classifier_latencies.append(v.latency_ms)
            classifier_errors += 1 if v.error else 0
        for i, v in zip(todo_a, verdicts[: len(todo_a)]):
            attack_l2[i] = v.is_blocking
        for i, v in zip(todo_b, verdicts[len(todo_a):]):
            benign_l2[i] = v.is_blocking

    def combined(l1: list, l2: list) -> list[bool]:
        return [a or bool(b) for a, b in zip(l1, l2)]

    attack_both = combined(attack_l1, attack_l2)
    benign_both = combined(benign_l1, benign_l2)

    per_category: dict[str, dict] = {}
    for (cat, _), d1, d12 in zip(attacks, attack_l1, attack_both):
        c = per_category.setdefault(cat, {"total": 0, "layer1": 0, "combined": 0})
        c["total"] += 1
        c["layer1"] += d1
        c["combined"] += d12

    missed = [
        {"category": cat, "text": text[:160]}
        for (cat, text), d12 in zip(attacks, attack_both)
        if not d12
    ]

    return {
        "key": key,
        "label": CORPORA[key]["label"],
        "note": CORPORA[key]["note"],
        "attacks": len(attacks),
        "benign": len(benign),
        "layer1": {"detected": sum(attack_l1), "false_positives": sum(benign_l1)},
        "combined": (
            {"detected": sum(attack_both), "false_positives": sum(benign_both)} if use_layer2 else None
        ),
        "per_category": [{"category": k, **v} for k, v in sorted(per_category.items())],
        "missed": missed[:25],
        "latency": {
            "rules": describe(rules_latencies),
            "classifier": describe(classifier_latencies) if use_layer2 else None,
        },
        "classifier_errors": classifier_errors,
    }


async def run(layer2: bool = False) -> dict:
    """Rejoue les trois corpus. `layer2=True` ajoute le classifieur IA (payant)."""
    global _last_result, _last_layer2_run

    use_layer2 = layer2 and llm_classifier.is_enabled()
    if use_layer2 and time.time() - _last_layer2_run < LAYER2_COOLDOWN_S and _last_result:
        # Évite qu'un double clic (ou un visiteur de la démo) relance 150 appels payants.
        return {**_last_result, "cached": True}

    async with _lock:
        t0 = time.perf_counter()
        corpora = [await _run_corpus(key, use_layer2) for key in CORPORA]
        result = {
            "ran_at": time.time(),
            "duration_ms": round((time.perf_counter() - t0) * 1000, 1),
            "layer2_requested": layer2,
            "layer2_used": use_layer2,
            "classifier": llm_classifier.status(),
            "corpora": corpora,
            "cached": False,
        }
        _last_result = result
        if use_layer2:
            _last_layer2_run = time.time()
        return result


def last() -> dict | None:
    return _last_result
