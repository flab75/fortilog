# SPDX-License-Identifier: AGPL-3.0-or-later
"""Constantes et petits helpers partagés entre modules (évite la duplication)."""
from __future__ import annotations
import copy
from pathlib import Path

import pandas as pd
import yaml

# Dossier du projet (celui qui contient config.yaml, data/, app.py).
PROJECT_DIR = Path(__file__).resolve().parent.parent

# Clés du config.yaml désignant un fichier local (résolues par resolve_paths).
PATH_KEYS = ("geo_db_path", "asn_db_path", "fortinet_ranges_file")


def resolve_paths(cfg: dict, base_dir) -> dict:
    """Copie de `cfg` où chaque chemin RELATIF de fichier de base (géo, ASN, plages
    Fortinet, listes de réputation) est rendu absolu par rapport à `base_dir` (`~` est
    développé). C'est ce qui rend l'outil indépendant du dossier courant : un config
    `data/geo/x.csv` désigne toujours le fichier à côté du config, d'où qu'on lance."""
    out = copy.deepcopy(cfg or {})
    base = Path(base_dir)

    def _abs(p):
        q = Path(str(p)).expanduser()
        return str(q if q.is_absolute() else (base / q).resolve())

    for k in PATH_KEYS:
        if out.get(k):
            out[k] = _abs(out[k])
    rl = out.get("reputation_lists")
    if isinstance(rl, list):
        for i, e in enumerate(rl):
            if isinstance(e, dict) and e.get("path"):
                e["path"] = _abs(e["path"])
            elif isinstance(e, str) and e:
                rl[i] = _abs(e)
    return out


def load_config(config_path) -> dict:
    """Charge un config.yaml et résout ses chemins relatifs par rapport à SON dossier."""
    p = Path(config_path)
    return resolve_paths(yaml.safe_load(p.read_text(encoding="utf-8")) or {}, p.resolve().parent)


def ssl_context():
    """Contexte TLS des téléchargements (maj_bases, ARIN) : magasin `certifi` s'il est
    installé, sinon celui du système. Indispensable avec le Python de python.org sur macOS,
    livré SANS certificats racine (bug rencontré : CERTIFICATE_VERIFY_FAILED sur tout
    téléchargement tant que « Install Certificates.command » n'a pas été lancé)."""
    import ssl
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def project_config_path(project_dir=None) -> Path:
    """Référentiel du projet : `config.local.yaml` (vraies valeurs, gitignoré) s'il existe,
    sinon `config.yaml` (versionné, ANONYMISÉ). Préférer le local évite d'analyser de vrais
    logs avec le référentiel d'exemple — cas réel : le pare-feu lui-même sortait en tête des
    « acteurs à investiguer » parce que son WAN n'était pas celui du config anonymisé."""
    d = Path(project_dir) if project_dir else PROJECT_DIR
    local = d / "config.local.yaml"
    return local if local.exists() else d / "config.yaml"


def default_config_path() -> str:
    """`config.yaml` du dossier courant s'il existe, sinon le référentiel du projet
    (`project_config_path`) — le CLI fonctionne ainsi lancé depuis n'importe quel dossier."""
    return "config.yaml" if Path("config.yaml").exists() else str(project_config_path())

# Ordre de sévérité (rang croissant) — sert au tri/au classement des constats.
SEV_ORDER = {"info": 0, "faible": 1, "moyen": 2, "eleve": 3, "critique": 4}

# Chemins de config FortiGate désignant un compte admin/SSO/API.
# Partagé entre la détection (detect) et la corrélation de chaînes (correlate).
CFG_ACCOUNT_PATHS = {
    "system.admin", "system.sso-forticloud-admin",
    "system.sso-fortigate-cloud-admin", "system.sso-admin", "system.api-user",
}


# Libellés FortiGate d'un échec d'authentification (admin GUI/SSH et portail SSL-VPN).
# Le champ `reason` ne distingue pas compte inconnu / mot de passe erroné côté SSL-VPN :
# ne jamais s'en servir pour conclure (cf. R16 dans detect.py).
FAIL_LOGDESC = ("Admin login failed", "SSL VPN login fail")


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
    "Échecs de login ciblant un compte du référentiel (SUSPICION)": "T1110 — Brute Force",
    "Accès réussi hors des pays attendus (SUSPICION)": "T1078 — Valid Accounts",
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
