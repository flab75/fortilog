"""Découverte des fichiers et détection automatique du type de log (par contenu)."""
from __future__ import annotations
from pathlib import Path
from collections import Counter

import pandas as pd

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

# Colonnes conservées au parsing (le reste des champs FortiGate est ignoré).
TARGET_COLS = ["date", "time", "tz", "eventtime", "logid", "type", "subtype",
               "level", "logdesc", "user", "ui", "method", "srcip", "dstip",
               "srcport", "dstport", "action", "status", "reason", "group",
               "cfgpath", "cfgobj", "cfgattr", "remip", "tunnelip", "tunneltype",
               "service", "sentbyte", "rcvdbyte", "msg",
               # utm/app-ctrl
               "appid", "appcat", "app", "hostname", "apprisk", "direction", "policyid",
               # event/security-rating
               "auditscore", "criticalcount", "highcount", "mediumcount",
               "lowcount", "passedcount", "auditreporttype", "auditid"]


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


def load_file(path) -> pd.DataFrame:
    """Parse un fichier de log en DataFrame, réduit aux colonnes utiles (TARGET_COLS)."""
    keep = set(TARGET_COLS)
    recs = []
    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = parse_line(line)
            recs.append({k: d.get(k, "") for k in keep})  # colonnes utiles seulement
    df = pd.DataFrame.from_records(recs, columns=TARGET_COLS)
    df["source_file"] = Path(path).name
    return df
