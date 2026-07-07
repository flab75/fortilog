# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fraîcheur des bases hors-ligne (géo/ASN/réputation/plages Fortinet) : âge en jours
depuis mtime, seuil `bases.age_max_jours` (défaut 90). Jamais bloquant — un âge
inconnu ou dépassé n'empêche pas l'analyse, il est seulement signalé."""
from __future__ import annotations
import time
from pathlib import Path

AGE_MAX_DEFAUT = 90


def _entree(nom: str, path, age_max: int) -> dict:
    p = Path(path)
    if not p.exists():
        return {"nom": nom, "path": str(path), "age_jours": None, "perime": False}
    age = int((time.time() - p.stat().st_mtime) // 86400)
    return {"nom": nom, "path": str(path), "age_jours": age, "perime": age > age_max}


def check_bases(cfg: dict) -> list:
    """Liste des bases configurées avec leur âge. Chemins absents du config -> ignorés
    (pas d'enrichissement demandé, comportement inchangé)."""
    age_max = int((cfg.get("bases") or {}).get("age_max_jours", AGE_MAX_DEFAUT))
    out = []
    if cfg.get("geo_db_path"):
        out.append(_entree("Géo (pays)", cfg["geo_db_path"], age_max))
    if cfg.get("asn_db_path"):
        out.append(_entree("ASN", cfg["asn_db_path"], age_max))
    if cfg.get("fortinet_ranges_file"):
        out.append(_entree("Plages Fortinet", cfg["fortinet_ranges_file"], age_max))
    for entry in (cfg.get("reputation_lists") or []):
        out.append(_entree(entry.get("nom", entry.get("path", "?")), entry.get("path", ""), age_max))
    return out
