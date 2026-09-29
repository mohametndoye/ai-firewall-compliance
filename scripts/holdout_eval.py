"""Évalue un lot hors échantillon : python scripts/holdout_eval.py a|b"""
import importlib, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "tests"))
from app.detectors import injection

mod = importlib.import_module(f"redteam_holdout_{sys.argv[1]}")
miss = [(c, t, injection.scan(t).score) for c, t in mod.ATTACKS if not injection.scan(t).is_blocked]
fp = [(t, injection.scan(t).score, injection.scan(t).matched_rules) for t in mod.BENIGN if injection.scan(t).is_blocked]
n = len(mod.ATTACKS)
print(f"Détectées : {n - len(miss)}/{n} ({100 * (n - len(miss)) / n:.0f} %)   Faux positifs : {len(fp)}/{len(mod.BENIGN)}")
print("\nMANQUÉES :"); [print(f"  [{c}] (score {s}) {t[:100]}") for c, t, s in miss]
print("\nFAUX POSITIFS :"); [print(f"  (score {s}) {t[:100]} -> {m}") for t, s, m in fp]
