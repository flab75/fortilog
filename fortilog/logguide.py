# SPDX-License-Identifier: AGPL-3.0-or-later
"""Guide des fichiers de log : à quoi sert chaque export, et lesquels sont inutiles ici.

Catalogue STATIQUE (aucune déduction) : chaque entrée dit ce que le type contient, ce que
l'outil en fait réellement, et si le déposer apporte quelque chose. Ce que l'outil
n'exploite pas est dit tel quel — un fichier inutile pour CETTE analyse peut rester utile
ailleurs (dépannage réseau, facturation), ce n'est jamais « à supprimer ».
"""
from __future__ import annotations
import pandas as pd

GUIDE_COLS = ["type de log", "contenu", "ce que l'outil en fait", "utilité", "présent"]

# (type, subtype) -> (contenu, ce que l'outil en fait, utilité)
LOG_GUIDE = {
    ("event", "vpn"): (
        "Connexions SSL-VPN et IPsec : tunnel up/down + motif, statistiques de session, "
        "échecs de login, bruit TLS (alert/new connection/exit error).",
        "Encart « Sessions VPN » (1 ligne = 1 tunnel), R3 (tunnel hors référentiel), "
        "R16 (échecs ciblant un compte réel), R17 (pays), géo + réputation des IP.",
        "INDISPENSABLE — c'est le seul fichier requis pour l'analyse VPN seule."),
    ("event", "system"): (
        "Vie de l'équipement : logins admin (GUI/SSH) réussis et échoués, changements de "
        "configuration, téléchargements de config/logs, automation.",
        "R1, R2, R4-R7, R11 (brute-force abouti), R12 (horaires), R14/R15 (nouvelle IP / "
        "impossible travel), chaînes IoC, comparaison de configuration (qui / quand).",
        "INDISPENSABLE pour l'analyse d'administration (compromission du boîtier)."),
    ("event", "user"): (
        "Authentifications applicatives (`Authentication logon/logout`) et bruit interne "
        "du firmware (« Seeding from entropy source »).",
        "Parsé et agrégé ; aucune règle dédiée.",
        "Accessoire — corrobore les sessions VPN, n'ajoute aucune détection."),
    ("event", "endpoint"): (
        "État FortiClient des postes (`FortiClient VPN connected/disconnected`).",
        "Parsé et agrégé ; aucune règle dédiée.",
        "Accessoire — doublon du point de vue VPN (event/vpn dit la même chose, avec l'IP "
        "publique et le motif de clôture)."),
    ("event", "security-rating"): (
        "Score de durcissement calculé par le boîtier (audit de bonnes pratiques).",
        "Repris tel quel dans le rapport texte (bilan hardening).",
        "Utile en contexte — ce n'est PAS une détection de compromission."),
    ("traffic", "local"): (
        "Trafic à destination ou en provenance du boîtier lui-même.",
        "R8 (sortie vers une destination non listée), R9 (pool VPN vers management), "
        "volumétrie et sources externes.",
        "Utile — surface les canaux sortants du boîtier ; volumineux."),
    ("traffic", "forward"): (
        "Trafic traversant (postes -> Internet), le plus gros volume de tous.",
        "R8/R9, volumétrie, top des sources externes.",
        "Optionnel et LOURD — n'apporte qu'un contexte d'exfiltration ; à déposer seulement "
        "si la question porte sur ce qu'une session a fait."),
    ("utm", "app-ctrl"): (
        "Contrôle applicatif : applications vues, bloquées, niveau de risque.",
        "R10 (application bloquée, `apprisk=critical`, catégorie Proxy).",
        "Utile si la licence UTM est active."),
    ("utm", "ips"): ("Signatures IPS déclenchées.",
                     "Agrégats descriptifs (top signatures) — aucune règle d'alerte.",
                     "Descriptif seulement."),
    ("utm", "webfilter"): ("Filtrage web : domaines et catégories bloqués.",
                           "Agrégats descriptifs (top domaines/catégories).",
                           "Descriptif seulement."),
    ("utm", "dns"): ("Requêtes DNS filtrées.", "Agrégats descriptifs.", "Descriptif seulement."),
    ("utm", "antivirus"): ("Verdicts antivirus.", "Agrégats descriptifs (top verdicts).",
                           "Descriptif seulement."),
    ("utm", "waf"): ("Pare-feu applicatif web.", "Parsé, agrégé ; aucune règle dédiée.",
                     "Descriptif seulement."),
}

INCONNU = ("Type non reconnu par l'outil.",
           "Parsing générique clé=valeur, marqué « (NON RECONNU) » ; aucune règle.",
           "Aucune détection — le contenu est visible dans « Données unifiées ».")

NOTES = [
    "Préfixe du nom de fichier : `memory-…` = tampon interne du boîtier, `forticloud-…` = "
    "archive FortiCloud. Les deux portent le MÊME format ; ils se recouvrent partiellement "
    "et la déduplication retire les doublons — déposer les deux ne fausse rien et couvre "
    "une période plus large (sur l'export du 08/09/2026, `memory-event-vpn` couvrait le "
    "01→08/09 quand `forticloud-event-vpn` s'arrêtait au 07/09).",
    "Pour l'analyse VPN seule, il suffit des fichiers `*-event-vpn-*.log`.",
    "Les `.conf` (backups de configuration) ne sont pas des logs : ils alimentent l'audit "
    "de configuration, la 2FA des comptes et la comparaison à une référence.",
    "« Inutile » signifie : sans effet sur CETTE analyse. Ces fichiers gardent leur utilité "
    "pour le dépannage réseau ou la volumétrie.",
]


def build_guide(meta_files) -> pd.DataFrame:
    """Catalogue complet, avec une colonne disant lesquels sont présents dans l'analyse."""
    presents = {}
    for f in (meta_files or []):
        if f.get("type") == "config":
            continue
        presents.setdefault((f.get("type", ""), f.get("subtype", "")), []).append(
            f"{f.get('name', '')} ({f.get('rows', 0)} lignes)")
    rows = []
    for key, (contenu, usage, utilite) in LOG_GUIDE.items():
        rows.append({"type de log": f"{key[0]}/{key[1]}", "contenu": contenu,
                     "ce que l'outil en fait": usage, "utilité": utilite,
                     "présent": " ; ".join(presents.pop(key, [])) or "non déposé"})
    for key, noms in presents.items():   # types hors catalogue : dits tels quels
        rows.append({"type de log": f"{key[0]}/{key[1]}", "contenu": INCONNU[0],
                     "ce que l'outil en fait": INCONNU[1], "utilité": INCONNU[2],
                     "présent": " ; ".join(noms)})
    return pd.DataFrame(rows, columns=GUIDE_COLS)


def guide_markdown(meta_files) -> str:
    """Même contenu en texte (rapport, onglet Streamlit)."""
    L = ["# GUIDE DES FICHIERS DE LOG", ""]
    for _, r in build_guide(meta_files).iterrows():
        L.append(f"**{r['type de log']}** — {r['utilité']}")
        L.append(f"  - contenu : {r['contenu']}")
        L.append(f"  - exploité par : {r['ce que l\'outil en fait']}")
        L.append(f"  - dans cette analyse : {r['présent']}")
        L.append("")
    L += ["## À retenir", ""] + [f"- {n}" for n in NOTES]
    return "\n".join(L)
