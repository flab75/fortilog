# SPDX-License-Identifier: AGPL-3.0-or-later
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

# Colonnes réellement consommées par une analyse (détection, dédup, agrégats,
# corrélation, géo, security-rating) ou nécessaires aux dérivées (timestamp/boîtier).
# Le frame d'analyse ne garde que celles-ci : une colonne objet coûte ~8 o/cellule
# rien qu'en pointeurs, donc en RETIRER est le plus gros levier mémoire.
ANALYSIS_COLS = ["date", "time", "eventtime", "logid", "type", "subtype", "logdesc",
                 "user", "ui", "srcip", "dstip", "action", "status", "reason", "group",
                 "cfgpath", "cfgobj", "app", "appcat", "apprisk", "hostname",
                 "auditscore", "criticalcount", "highcount", "mediumcount",
                 "lowcount", "passedcount", "auditreporttype"]

# Le reste de TARGET_COLS : uniquement pour la feuille Excel « Données unifiées »,
# jamais lu par une analyse -> relu à la demande pour les seules lignes affichées.
DISPLAY_ONLY_COLS = [c for c in TARGET_COLS if c not in ANALYSIS_COLS]


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


def load_file(path, columns: list | None = None) -> pd.DataFrame:
    """Parse un fichier de log en DataFrame (construction COLONNAIRE : dict de listes
    plutôt qu'une liste de dicts -> évite de matérialiser N dicts de ~45 clés en même
    temps que le DataFrame ; pic mémoire de parsing ~4-5× plus bas sur les gros fichiers).

    `columns` : sous-ensemble de colonnes à conserver (défaut TARGET_COLS). Le frame
    d'analyse n'a besoin que de ANALYSIS_COLS. Ajoute toujours `source_file` et `_row`
    (index de la ligne non vide dans le fichier) — clé stable entre passes pour relire
    les colonnes d'affichage à la demande (cf. load_columns_for_rows)."""
    keep = list(columns) if columns is not None else TARGET_COLS
    cols: dict[str, list] = {k: [] for k in keep}
    appenders = [(k, cols[k].append) for k in keep]  # bind des .append (boucle chaude)
    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = parse_line(line)
            for k, append in appenders:
                append(d.get(k, ""))
    df = pd.DataFrame(cols, columns=keep)
    df["source_file"] = Path(path).name
    df["_row"] = range(len(df))
    return df


def load_columns_for_rows(files, wanted: set, columns) -> pd.DataFrame:
    """2ᵉ passe : relit `files` et ne matérialise QUE les lignes dont (source_file, _row)
    ∈ `wanted`. Renvoie un DataFrame [columns + source_file + _row]. Permet de
    reconstituer les colonnes d'affichage sans les porter pour toutes les lignes durant
    l'analyse. La logique de saut des lignes vides est identique à load_file (les `_row`
    coïncident)."""
    columns = list(columns)
    data: dict[str, list] = {c: [] for c in columns}
    sf_col: list = []
    row_col: list = []
    for f in files:
        name = f.name
        want = {r for (s, r) in wanted if s == name}
        if not want:
            continue
        i = -1
        with open(f, errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                i += 1
                if i in want:
                    d = parse_line(line)
                    for c in columns:
                        data[c].append(d.get(c, ""))
                    sf_col.append(name)
                    row_col.append(i)
    df = pd.DataFrame(data, columns=columns)
    df["source_file"] = sf_col
    df["_row"] = row_col
    return df
