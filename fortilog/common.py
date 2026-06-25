# SPDX-License-Identifier: AGPL-3.0-or-later
"""Constantes et petits helpers partagés entre modules (évite la duplication)."""
from __future__ import annotations
import pandas as pd

# Ordre de sévérité (rang croissant) — sert au tri/au classement des constats.
SEV_ORDER = {"info": 0, "faible": 1, "moyen": 2, "eleve": 3, "critique": 4}

# Chemins de config FortiGate désignant un compte admin/SSO/API.
# Partagé entre la détection (detect) et la corrélation de chaînes (correlate).
CFG_ACCOUNT_PATHS = {
    "system.admin", "system.sso-forticloud-admin",
    "system.sso-fortigate-cloud-admin", "system.sso-admin", "system.api-user",
}


def str_col(df: pd.DataFrame, name: str) -> pd.Series:
    """Colonne `name` du DataFrame en chaîne (NaN -> ''), série vide alignée si absente."""
    return df.get(name, pd.Series([""] * len(df), index=df.index)).fillna("").astype(str)
