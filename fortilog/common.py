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


# Mapping INDICATIF règle -> technique MITRE ATT&CK (aide au reporting, jamais une
# attribution). Clés = libellés exacts des règles de detect.py ; règle absente -> champ
# vide. ID et noms vérifiés sur attack.mitre.org le 2026-07-07.
MITRE_MAP = {
    # R1 — logins admin (usage de comptes valides)
    "Login admin réussi depuis source externe": "T1078 — Valid Accounts",
    "Login admin réussi par compte hors référentiel": "T1078 — Valid Accounts",
    "Login admin réussi (interne, connu)": "T1078 — Valid Accounts",
    "Login admin réussi, source indéterminée (srcip absent)": "T1078 — Valid Accounts",
    # R2 / R11 / R13 — brute force
    "Brute-force sur COMPTE VALIDE (passwd_invalid)": "T1110 — Brute Force",
    "Brute-force potentiellement réussi depuis source externe (SUSPICION)": "T1110 — Brute Force",
    "Succès admin après rafale d'échecs (interne — SUSPICION)": "T1110 — Brute Force",
    "Rafale d'échecs sur comptes inexistants — name_invalid (SUSPICION)": "T1110 — Brute Force",
    # R3 — accès distant externe
    "Tunnel SSL-VPN établi hors référentiel": "T1133 — External Remote Services",
    # R4 / R5 — création/modification de comptes
    "Modif config compte": "T1136 — Create Account",
    "Nom de compte potentiellement voyou (SUSPICION)": "T1136 — Create Account",
    # R6 — collecte de données du boîtier
    "Téléchargement de config via GUI": "T1005 — Data from Local System",
    "Téléchargement de logs via GUI": "T1005 — Data from Local System",
    # R7 — persistance planifiée
    "Automation déclenchée (vérifier action-type en config)": "T1053 — Scheduled Task/Job",
    # R8 — sortie boîtier non listée
    "Trafic sortant du boîtier vers destination non listée": "T1041 — Exfiltration Over C2 Channel",
    # R9 — services distants internes
    "Accès depuis pool VPN vers management": "T1021 — Remote Services",
    # R10 — contrôle applicatif / proxy
    "Application bloquée par contrôle applicatif (UTM/app-ctrl)": "T1090 — Proxy",
    "Application à risque critique non bloquée (SUSPICION — UTM/app-ctrl)": "T1090 — Proxy",
    "Trafic via outil de proxy/anonymisation (UTM/app-ctrl)": "T1090 — Proxy",
    # R12 — anomalie d'usage d'un compte valide
    "Login admin hors horaires ouvrés (SUSPICION comportementale)": "T1078 — Valid Accounts",
    # R14 / R15 — nouveauté comportementale par compte admin / impossible travel
    "Connexion admin depuis une IP non vue plus tôt dans cette analyse "
    "(SUSPICION comportementale)": "T1078 — Valid Accounts",
    "Connexion admin depuis un pays non vu plus tôt dans cette analyse "
    "(SUSPICION comportementale)": "T1078 — Valid Accounts",
    "Connexion admin depuis un pays jamais vu pour ce compte, historique inclus "
    "(SUSPICION comportementale)": "T1078 — Valid Accounts",
    "Connexions admin depuis pays incompatibles en fenêtre courte — impossible travel "
    "(SUSPICION)": "T1078 — Valid Accounts",
}


def str_col(df: pd.DataFrame, name: str) -> pd.Series:
    """Colonne `name` du DataFrame en chaîne (NaN -> ''), série vide alignée si absente."""
    return df.get(name, pd.Series([""] * len(df), index=df.index)).fillna("").astype(str)
