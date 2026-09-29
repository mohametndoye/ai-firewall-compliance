"""Mesure le taux de détection, les faux positifs et la latence du détecteur.

Usage :
    python scripts/redteam_report.py            # affiche le résumé
    python scripts/redteam_report.py --write    # écrit docs/rapport_red_team.md
"""
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from app.detectors import injection  # noqa: E402
from redteam_corpus import ATTACKS, BENIGN  # noqa: E402


def run():
    per_cat = defaultdict(lambda: [0, 0])
    missed, false_pos, latencies = [], [], []

    for cat, text in ATTACKS:
        t0 = time.perf_counter()
        r = injection.scan(text)
        latencies.append((time.perf_counter() - t0) * 1000)
        per_cat[cat][1] += 1
        if r.is_blocked:
            per_cat[cat][0] += 1
        else:
            missed.append((cat, text, r.score))

    for _, text in BENIGN:
        t0 = time.perf_counter()
        r = injection.scan(text)
        latencies.append((time.perf_counter() - t0) * 1000)
        if r.is_blocked:
            false_pos.append((text, r.score, r.matched_rules))

    return per_cat, missed, false_pos, latencies


def main():
    per_cat, missed, false_pos, lat = run()
    total = sum(v[1] for v in per_cat.values())
    detected = sum(v[0] for v in per_cat.values())

    lines = ["# Rapport de red teaming — détecteur d'injection", ""]
    lines.append(f"**Attaques détectées : {detected}/{total} ({100 * detected / total:.0f} %)**  ")
    lines.append(f"**Faux positifs : {len(false_pos)}/{len(BENIGN)} ({100 * len(false_pos) / len(BENIGN):.0f} %)**  ")
    lines.append(
        f"**Latence du scan** : médiane {statistics.median(lat):.2f} ms, "
        f"95e centile {sorted(lat)[int(len(lat) * 0.95) - 1]:.2f} ms, max {max(lat):.2f} ms"
    )
    lines += ["", "| Catégorie | Détectées | Total |", "|---|---|---|"]
    for cat, (d, t) in sorted(per_cat.items()):
        lines.append(f"| {cat} | {d} | {t} |")

    lines += ["", "## Attaques non détectées"]
    lines += [f"- [{c}] (score {s}) `{t[:110]}`" for c, t, s in missed] or ["- aucune sur ce corpus"]
    lines += ["", "## Faux positifs"]
    lines += [f"- (score {s}) `{t[:110]}` → {m}" for t, s, m in false_pos] or ["- aucun sur ce corpus"]
    lines += [
        "",
        "## Limites",
        "Ces chiffres portent sur un corpus rédigé par l'équipe du projet. Ils mesurent la "
        "robustesse face aux techniques *connues et anticipées*, pas face à une technique "
        "inédite. Un détecteur par règles ne peut pas garantir l'absence de contournement ; "
        "voir la section « Limites et défense en profondeur » du README.",
    ]

    out = "\n".join(lines)
    print(out)
    if "--write" in sys.argv:
        (ROOT / "docs" / "rapport_red_team.md").write_text(out + "\n", encoding="utf-8")
        print("\n-> écrit dans docs/rapport_red_team.md")


if __name__ == "__main__":
    main()
