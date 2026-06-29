# SPDX-License-Identifier: AGPL-3.0-or-later
"""Génère un référentiel `config.yaml` (BROUILLON) depuis un ou plusieurs .conf FortiGate.

Principe directeur respecté : l'outil DÉRIVE ce qui est lisible dans la configuration
(noms d'admins, interfaces/plages internes, utilisateurs locaux, groupes/utilisateurs
VPN, peers IPsec, DNS) ; il NE DEVINE PAS le reste (les paramètres d'analyse sont
remplis avec les valeurs par défaut du projet). Le fichier produit est un POINT DE
DÉPART À RELIRE — jamais un référentiel définitif. Aucun secret (mot de passe, clé)
n'est extrait : le référentiel ne contient que des noms, des IP et des plages.

Réutilise le parseur CLI FortiGate de `confaudit` (config/edit/set en arbre).
CLI : `python -m fortilog.confgen FW-T1.conf [FW-T2.conf ...] [-o config.generated.yaml] [--force]`
"""
from __future__ import annotations
import argparse
import ipaddress
import re
from datetime import date
from pathlib import Path

from .confaudit import parse_config, find_blocks

_QUOTED = re.compile(r'"([^"]*)"|(\S+)')


def _values(raw) -> list[str]:
    """Découpe une valeur FortiGate multi-tokens : '"a" "b c"' -> ['a', 'b c']."""
    if not raw:
        return []
    return [a if a else b for a, b in _QUOTED.findall(str(raw))]


def _edits(root, header):
    """Itère les blocs `edit` sous tous les `config <header>` de l'arbre."""
    for blk in find_blocks(root, header):
        for e in blk.children:
            if e.kind == "edit":
                yield e


def _iface_addr(ipval) -> str:
    """Adresse hôte d'un `set ip <addr> <mask>` (sans le masque) ; '' si absent."""
    parts = str(ipval or "").split()
    return parts[0] if parts else ""


def _iface_net(ipval):
    """'10.10.1.1 255.255.255.0' -> ip_network 10.10.1.0/24 (ou None)."""
    parts = str(ipval or "").split()
    if len(parts) < 2:
        return None
    try:
        return ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
    except ValueError:
        return None


def _hostname(root) -> str:
    g = find_blocks(root, "system global")
    return g[0].settings.get("hostname", "").strip('"') if g else ""


def _ip_key(s):
    try:
        return int(ipaddress.ip_address(str(s)))
    except ValueError:
        return 0


def _net_key(s):
    try:
        return int(ipaddress.ip_network(str(s), strict=False).network_address)
    except ValueError:
        return 0


def extract_one(text: str, fallback_name: str) -> dict:
    """Extrait le référentiel dérivable d'UN .conf. `mgmt` est heuristique (à vérifier)."""
    root = parse_config(text)
    name = _hostname(root) or fallback_name

    wan_ips: list[str] = []
    plages: list[str] = []
    mgmt_named = None
    mgmt_candidates: list[tuple[int, str]] = []
    for itf in _edits(root, "system interface"):
        net = _iface_net(itf.settings.get("ip"))
        if net is None or net.version != 4:
            continue
        role = itf.settings.get("role", "").strip('"').lower()
        access = itf.settings.get("allowaccess", "")
        addr = _iface_addr(itf.settings.get("ip"))
        if role == "wan" and not net.network_address.is_private:
            wan_ips.append(addr)
        if role in ("lan", "dmz") and net.network_address.is_private:
            plages.append(str(net))
            if "https" in access or "ssh" in access:
                mgmt_candidates.append((net.prefixlen, addr))
        if itf.name.lower() in ("mgmt", "mgmt1", "mgmt2", "management") and addr:
            mgmt_named = addr
    # mgmt : interface explicitement nommée, sinon LAN d'admin le plus spécifique (à vérifier)
    mgmt = mgmt_named or (sorted(mgmt_candidates, reverse=True)[0][1] if mgmt_candidates else None)
    mgmt_heuristique = mgmt is not None and mgmt_named is None

    admins = [e.name for e in _edits(root, "system admin")]
    admins += [e.name for e in _edits(root, "system sso-admin")]
    locaux = [e.name for e in _edits(root, "user local")]

    members = {e.name: _values(e.settings.get("member")) for e in _edits(root, "user group")}
    vpn_groups: list[str] = []
    for rule in _edits(root, "authentication-rule"):
        vpn_groups += _values(rule.settings.get("groups"))
    local_set = set(locaux)
    vpn_users = sorted({m for g in vpn_groups for m in members.get(g, []) if m in local_set})

    peers = [e.settings.get("remote-gw", "").strip() for e in _edits(root, "vpn ipsec phase1-interface")]
    peers = [p for p in peers if p]
    dns_ips = []
    dns = find_blocks(root, "system dns")
    if dns:
        for k in ("primary", "secondary"):
            v = dns[0].settings.get(k, "").strip()
            if v:
                dns_ips.append(v)
    logging = []
    for hdr in ("log fortianalyzer setting", "log syslogd setting"):
        for blk in find_blocks(root, hdr):
            v = blk.settings.get("server", "").strip().strip('"')
            if v:
                logging.append(v)

    return {
        "name": name, "wan": wan_ips[0] if wan_ips else None, "wan_all": wan_ips,
        "mgmt": mgmt, "mgmt_heuristique": mgmt_heuristique,
        "plages": plages, "admins": admins, "locaux": locaux,
        "vpn_groups": vpn_groups, "vpn_users": vpn_users,
        "ipsec_peers": peers, "dns": dns_ips, "logging": logging,
    }


def extract_referential(confs: dict) -> dict:
    """confs = {nom_fichier: texte}. Fusionne plusieurs .conf en un référentiel
    (un .conf = un boîtier ; admins/plages/VPN unionnés, utilisateurs locaux par boîtier)."""
    ones = [extract_one(t, Path(n).stem) for n, t in confs.items()]
    boitiers, locaux = {}, {}
    admins, plages, vpn_groups, vpn_users = set(), set(), set(), set()
    peers, dns, logging = set(), set(), set()
    heuristic_mgmt: list[str] = []
    for o in ones:
        boitiers[o["name"]] = {"wan": o["wan"], "mgmt": o["mgmt"], "wan_all": o["wan_all"]}
        if o["mgmt_heuristique"]:
            heuristic_mgmt.append(o["name"])
        locaux[o["name"]] = sorted(set(o["locaux"]))
        admins |= set(o["admins"]); plages |= set(o["plages"])
        vpn_groups |= set(o["vpn_groups"]); vpn_users |= set(o["vpn_users"])
        peers |= set(o["ipsec_peers"]); dns |= set(o["dns"]); logging |= set(o["logging"])
    return {
        "boitiers": boitiers,
        "admins_connus": sorted(admins),
        "utilisateurs_vpn_actifs": sorted(vpn_users),
        "groupes_vpn_legitimes": sorted(vpn_groups),
        "utilisateurs_locaux": locaux,
        "plages_internes": sorted(plages, key=_net_key),
        "destinations_legitimes": {
            "ipsec_peers": sorted(peers, key=_ip_key),
            "dns": sorted(dns, key=_ip_key),
            "logging": sorted(logging, key=_ip_key),
            # Plages Fortinet statiques (FortiGuard/FortiCloud/FortiSASE) — indépendantes du .conf
            "fortiguard": [
                "192.35.158.0/24",
                "208.91.112.0/22",
                "173.243.128.0/20",
                "65.210.95.0/24",
                "139.138.105.0/24",
                "148.230.32.0/19",
            ],
            "ipv6_multicast": ["ff02::/16"],
        },
        "sources": list(confs.keys()),
        "mgmt_heuristique": heuristic_mgmt,
    }


# Paramètres NON dérivables d'un .conf : valeurs par défaut du projet (à ajuster au besoin).
_DEFAULTS = r"""
rafales:
  fenetre_minutes: 60
  mode_seuil: adaptatif      # adaptatif | fixe
  facteur_mediane: 3.0       # rafale si taux >= facteur * mediane
  seuil_fixe_optionnel: null # utilisé seulement si mode_seuil = fixe

# R11 — brute-force potentiellement réussi (login admin réussi précédé d'échecs). SUSPICION.
bruteforce:
  fenetre_minutes: 60
  seuil_echecs: 5

# R12 — horaires inhabituels (login admin réussi hors plage ouvrée). SUSPICION faible.
horaires_ouvres:
  debut: 7
  fin: 20
  alerte_weekend: true

# Corrélation temporelle (chaîne IoC) accès -> compte -> exfiltration. SUSPICION, pas preuve.
correlation:
  fenetre_minutes: 60
  sequence_requise: [ACCES, COMPTE, EXFILTRATION]

# Motifs heuristiques de comptes potentiellement voyous (SUSPICION, pas preuve)
comptes_suspects_regex:
  - '(?i)^admin[-_]?\d+$'
  - '(?i)^(access|support|test|backup|service)$'
  - '@(tutamail|protonmail|tutanota|mail\.io)\.'
  - '@forticloud\.com'

# Enrichissement géo/ASN HORS-LIGNE (optionnel). Bases locales license-clean à fournir.
geo_db_path: data/geo/dbip-country-lite.csv
asn_db_path: data/geo/ip2asn-v4.tsv
top_sources_externes: 50

# Listes de réputation IP HORS-LIGNE (threat intel, optionnel).
reputation_lists:
  - { nom: "FireHOL L1", path: data/geo/firehol_level1.netset }

# Liste blanche contrôle applicatif (UTM/app-ctrl) : hostnames à ne pas signaler.
app_ctrl_whitelist:
  - proxy-safebrowsing.googleapis.com

# Rapport de synthèse : nombre de constats/événements/IP détaillés par section.
rapport:
  max_constats: 5
"""


def _q(s) -> str:
    """Échappe une valeur scalaire pour YAML (quote si espace/caractère spécial)."""
    s = "" if s is None else str(s)
    if s and s == s.strip() and not re.search(r"""[\s:#'"\[\]{},&*?|<>=!%@`]""", s):
        return s
    return "'" + s.replace("'", "''") + "'"


def _inline(items) -> str:
    return "[" + ", ".join(_q(x) for x in items) + "]"


def render_config_yaml(ref: dict) -> str:
    """Rend le référentiel + les paramètres par défaut en un config.yaml commenté."""
    L: list[str] = []
    sources = ", ".join(ref.get("sources", [])) or "?"
    L.append(f"# config.yaml GÉNÉRÉ par fortilog.confgen le {date.today().isoformat()}")
    L.append(f"# Source(s) : {sources}")
    L.append("# ⚠ BROUILLON À RELIRE : les sections « référentiel » sont DÉRIVÉES des .conf ;")
    L.append("#   les paramètres ci-dessous sont les DÉFAUTS du projet. Vérifier les lignes")
    L.append("#   marquées « à vérifier / à compléter », puis renommer en config.local.yaml.")
    L.append("")

    L.append("boitiers:")
    for name, b in ref["boitiers"].items():
        wan = b["wan"] if b["wan"] else "null"
        mgmt = b["mgmt"] if b["mgmt"] else "null"
        note = "   # mgmt heuristique — à vérifier" if name in ref.get("mgmt_heuristique", []) else ""
        if not b["wan"]:
            note = "   # wan/mgmt non trouvés — à compléter"
        L.append(f"  {_q(name)}: {{ wan: {wan}, mgmt: {mgmt} }}{note}")
        if len(b.get("wan_all", [])) > 1:
            L.append(f"    # autres IP WAN détectées : {', '.join(b['wan_all'][1:])}")
    L.append("")

    L.append(f"admins_connus: {_inline(ref['admins_connus'])}")
    L.append("")
    L.append(f"utilisateurs_vpn_actifs: {_inline(ref['utilisateurs_vpn_actifs'])}")
    L.append(f"groupes_vpn_legitimes: {_inline(ref['groupes_vpn_legitimes'])}")
    L.append("")

    L.append("utilisateurs_locaux:")
    if ref["utilisateurs_locaux"]:
        for name, users in ref["utilisateurs_locaux"].items():
            L.append(f"  {_q(name)}: {_inline(users)}")
    else:
        L.append("  {}")
    L.append("")

    L.append("plages_internes:")
    if ref["plages_internes"]:
        for cidr in ref["plages_internes"]:
            L.append(f"  - {cidr}")
    else:
        L.append("  []   # aucune interface lan/dmz détectée — à compléter")
    L.append("")

    L.append("destinations_legitimes:")
    dl = ref["destinations_legitimes"]
    for group in ("ipsec_peers", "dns", "logging"):
        L.append(f"  {group}: {_inline(dl.get(group, []))}")
    L.append("  # Plages Fortinet (FortiGuard/FortiCloud/FortiSASE) — trafic boîtier légitime.")
    L.append("  fortiguard:")
    for cidr in dl.get("fortiguard", []):
        L.append(f"    - {cidr}")
    L.append("  # Multicast IPv6 lien-local — trafic réseau normal du boîtier (MLDv2).")
    L.append("  ipv6_multicast:")
    for cidr in dl.get("ipv6_multicast", []):
        L.append(f"    - {cidr}")
    L.append("")

    L.append(_DEFAULTS.strip("\n"))
    L.append("")

    L.append("# Indice de rattachement fichier -> boîtier (sous-chaînes de noms de fichiers de logs).")
    L.append("fichiers_boitier:")
    for name in ref["boitiers"]:
        L.append(f"  {_q(name)}: {_inline([name])}   # à compléter")
    L.append("")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(
        description="Génère un config.yaml (BROUILLON à relire) depuis des .conf FortiGate")
    ap.add_argument("confs", nargs="+", help="fichiers .conf FortiGate")
    ap.add_argument("-o", "--output", default="config.generated.yaml", help="fichier de sortie")
    ap.add_argument("--force", action="store_true", help="écraser le fichier de sortie s'il existe")
    a = ap.parse_args()

    confs = {Path(p).name: Path(p).read_text(errors="replace") for p in a.confs}
    ref = extract_referential(confs)
    text = render_config_yaml(ref)

    out = Path(a.output)
    if out.exists() and not a.force:
        raise SystemExit(f"{out} existe déjà — utiliser --force pour écraser.")
    out.write_text(text, encoding="utf-8")

    import yaml
    from .validate import validate_config
    errs = validate_config(yaml.safe_load(text))
    print(f">> Référentiel écrit : {out}")
    print(f"   Boîtiers : {', '.join(ref['boitiers']) or '—'}")
    print(f"   Admins : {len(ref['admins_connus'])} | plages internes : {len(ref['plages_internes'])} | "
          f"groupes VPN : {len(ref['groupes_vpn_legitimes'])} | utilisateurs VPN : {len(ref['utilisateurs_vpn_actifs'])}")
    if errs:
        print("   ⚠ validate_config :")
        for e in errs:
            print(f"     - {e}")
    print("   ⚠ BROUILLON à relire (mgmt heuristique, fichiers_boitier à compléter) avant usage.")


if __name__ == "__main__":
    main()
