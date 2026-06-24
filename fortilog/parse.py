"""Parsing robuste des logs FortiGate au format clé=valeur.

Hypothèse de format (vérifiée sur les exports fournis) : chaque ligne est une
suite de tokens `clé=valeur` séparés par des espaces ; une valeur est soit non
quotée (sans espace), soit entre guillemets doubles (et peut alors contenir des
espaces), p.ex. msg="User vpnuser2 added to auth logon".

Échappement Fortinet (P4.1) : à l'intérieur d'une valeur quotée, un guillemet
double littéral est échappé `\\"` et un backslash littéral est échappé `\\\\`.
Le parseur consomme ces échappements sans casser l'alignement des champs qui
SUIVENT (important pour app-ctrl, où `apprisk`/`scertcname` viennent après `msg`).
"""
from __future__ import annotations
import re

# clé : lettres/chiffres/_/- ; valeur :
#   - quotée : "..." où le contenu accepte les séquences échappées \X (dont \" et \\)
#   - non quotée : suite sans espace
# Le motif `(?:\\.|[^"\\])*` est LINÉAIRE (chaque caractère est consommé par une
# seule branche) -> pas de backtracking catastrophique sur de gros volumes.
_TOKEN_RE = re.compile(r'([A-Za-z0-9_\-]+)=("(?:\\.|[^"\\])*"|\S*)')


def _unescape(s: str) -> str:
    """Déséchappe le contenu d'une valeur quotée : \\X -> X (donc \\" -> \" et \\\\ -> \\)."""
    if "\\" not in s:
        return s
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            out.append(s[i + 1])
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def parse_line(line: str) -> dict[str, str]:
    """Transforme une ligne brute en dictionnaire clé->valeur (guillemets retirés,
    échappements résolus)."""
    out: dict[str, str] = {}
    for key, raw in _TOKEN_RE.findall(line):
        if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
            raw = _unescape(raw[1:-1])
        out[key] = raw
    return out
