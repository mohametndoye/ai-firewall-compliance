"""Test de charge : envoie un lot de requêtes variées au proxy, puis affiche les
latences mesurées par le pare-feu (route /v1/admin/metrics/performance).

Sert à obtenir des percentiles fiables pour le rapport : avec une dizaine de
requêtes, un P95 ou un P99 ne veut rien dire.

Usage :
    python scripts/charge.py                                  # 300 requêtes sur localhost:8000
    python scripts/charge.py --n 500 --url https://mon-backend.onrender.com
    python scripts/charge.py --concurrency 4                  # requêtes en parallèle

Mélange envoyé (proportions approximatives) : 60 % de requêtes normales, 20 %
avec données personnelles, 20 % d'attaques tirées du corpus Red Team.
Attention : si des clés API sont configurées sur le serveur visé, chaque requête
autorisée appelle le vrai modèle (et la couche IA) : cela a un coût.
"""
import argparse
import asyncio
import random
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from redteam_corpus import ATTACKS  # noqa: E402

NORMAL = [
    "Quelle est la capitale du Canada ?",
    "Résume-moi les avantages du télétravail en trois points.",
    "Peux-tu traduire « bonne journée » en anglais ?",
    "Explique la différence entre TCP et UDP.",
    "Écris une fonction Python qui inverse une chaîne.",
    "Quels sont les principes du RGPD ?",
    "Donne-moi une recette simple de soupe aux lentilles.",
    "Comment fonctionne une table de hachage ?",
]

PII = [
    "Je m'appelle Jean Tremblay, mon courriel est jean.tremblay@example.com",
    "Rappelle Marie au 819-555-0142 demain matin.",
    "Ma carte 4111 1111 1111 1111 a été refusée, que faire ?",
    "Envoie le rapport à sophie.martin@entreprise.ca avant midi.",
]


def pick() -> str:
    r = random.random()
    if r < 0.6:
        return random.choice(NORMAL)
    if r < 0.8:
        return random.choice(PII)
    return random.choice(ATTACKS)[1]


async def main(url: str, n: int, concurrency: int, provider: str, model: str) -> None:
    sem = asyncio.Semaphore(concurrency)
    statuses: dict[str, int] = {}

    async with httpx.AsyncClient(base_url=url, timeout=60) as client:

        async def one():
            async with sem:
                r = await client.post("/v1/proxy/chat", json={"provider": provider, "model": model, "prompt": pick()})
                key = r.json().get("status", f"http_{r.status_code}") if r.status_code == 200 else f"http_{r.status_code}"
                statuses[key] = statuses.get(key, 0) + 1

        t0 = time.perf_counter()
        await asyncio.gather(*(one() for _ in range(n)))
        elapsed = time.perf_counter() - t0

        perf = (await client.get("/v1/admin/metrics/performance", params={"limit": n})).json()

    fw = perf["firewall_without_classifier"]
    print(f"{n} requêtes envoyées en {elapsed:.1f} s ({n / elapsed:.0f} req/s)")
    print("Décisions :", ", ".join(f"{k} {v}" for k, v in sorted(statuses.items())))
    print()
    print(f"Latence ajoutée par le pare-feu (hors couche IA, LLM cible exclu), sur {fw['count']} requêtes :")
    print(f"  moyenne {fw['mean']} ms · P50 {fw['p50']} ms · P95 {fw['p95']} ms · P99 {fw['p99']} ms · max {fw['max']} ms")
    print(f"  cible : P95 < {perf['target_ms']} ms -> {'RESPECTÉE' if perf['meets_target'] else 'DÉPASSÉE'}")
    print()
    print("Par étape (moyenne / P95) :")
    for name, s in perf["stages"].items():
        if s["count"]:
            print(f"  {name:<11} {s['mean']:>9} ms / {s['p95']:>9} ms   ({s['count']} mesures)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--concurrency", type=int, default=1)
    ap.add_argument("--provider", default="anthropic")
    ap.add_argument("--model", default="claude-haiku-4-5-20251001")
    args = ap.parse_args()
    random.seed(42)
    asyncio.run(main(args.url, args.n, args.concurrency, args.provider, args.model))
