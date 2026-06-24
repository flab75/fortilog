"""Découverte des fichiers et détection automatique du type de log (par contenu)."""
from __future__ import annotations
from pathlib import Path
from collections import Counter
from .parse import parse_line

# Types UTM présents dans les exports mais sans règles dédiées : parsing générique.
UTM_NO_RULES = {
    ("utm", "ips"), ("utm", "webfilter"), ("utm", "dns"),
    ("utm", "antivirus"), ("utm", "waf"),
}

KNOWN_TYPES = {
    ("event", "system"), ("event", "user"), ("event", "vpn"),
    ("traffic", "local"), ("traffic", "forward"), ("utm", "app-ctrl"),
    ("app-ctrl", ""),  # certains exports n'ont que subtype
    ("event", "security-rating"),
    *UTM_NO_RULES,
}

LOG_GLOBS = ("*.log", "*.txt")


def list_log_files(folder: str | Path) -> list[Path]:
    folder = Path(folder)
    files: list[Path] = []
    for g in LOG_GLOBS:
        files.extend(sorted(folder.glob(g)))
    return files


def detect_type(file: str | Path, sample: int = 200) -> tuple[str, str, bool]:
    """Lit jusqu'à `sample` lignes, renvoie (type, subtype, reconnu)."""
    types: Counter = Counter()
    with open(file, errors="replace") as fh:
        for i, line in enumerate(fh):
            if i >= sample:
                break
            d = parse_line(line)
            t, s = d.get("type", ""), d.get("subtype", "")
            if t:
                types[(t, s)] += 1
    if not types:
        return ("", "", False)
    (t, s), _ = types.most_common(1)[0]
    reconnu = (t, s) in KNOWN_TYPES or (t, "") in KNOWN_TYPES
    return (t, s, reconnu)
