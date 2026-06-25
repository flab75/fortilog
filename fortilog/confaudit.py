# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit d'un fichier de configuration FortiGate (.conf) pour indices de compromission.

Le format est le CLI FortiGate : blocs `config <chemin>` / `edit "<nom>"` / `set k v` /
`next` / `end`, imbriqués. On parse en arbre puis on applique une grille d'audit
ANCRÉE sur le format réel (jamais inventée), comparée au référentiel `config.yaml`.

Principe directeur respecté : on SIGNALE (compte hors référentiel, admin sans
trusted-host, automation à action sensible…) ; le verdict reste humain. Toute
détection « hors référentiel » est une SUSPICION à confirmer (un admin légitime
récent n'est pas forcément dans le référentiel).
"""
from __future__ import annotations
import re
import pandas as pd

from .common import SEV_ORDER

# Comptes SSO FortiCloud auto-provisionnés (présents par défaut, non « voyous »).
_CLOUD_ACCOUNT_RE = re.compile(r"(fortigatecloud\.com$|^FortiGateCloud$|^FortiCloud)", re.I)
# Action-types d'automation à risque (exécution de commandes / sortie réseau).
SENSITIVE_AUTOMATION = {"cli-script", "webhook"}


class Block:
    __slots__ = ("kind", "header", "name", "settings", "children", "parent")

    def __init__(self, kind, header="", name="", parent=None):
        self.kind = kind          # 'root' | 'config' | 'edit'
        self.header = header      # pour 'config' : ex. 'system admin'
        self.name = name          # pour 'edit'   : ex. 'admin1'
        self.settings: dict[str, str] = {}
        self.children: list[Block] = []
        self.parent = parent


def parse_config(text: str) -> Block:
    """Parse le CLI FortiGate en arbre de blocs (tolérant : ignore lignes inconnues)."""
    root = Block("root")
    stack = [root]
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("config "):
            b = Block("config", header=line[7:].strip(), parent=stack[-1])
            stack[-1].children.append(b)
            stack.append(b)
        elif line.startswith("edit "):
            name = line[5:].strip().strip('"')
            b = Block("edit", name=name, parent=stack[-1])
            stack[-1].children.append(b)
            stack.append(b)
        elif line == "next":
            if len(stack) > 1 and stack[-1].kind == "edit":
                stack.pop()
        elif line == "end":
            if len(stack) > 1 and stack[-1].kind == "config":
                stack.pop()
        elif line.startswith("set "):
            k, _, v = line[4:].partition(" ")
            stack[-1].settings[k] = v.strip()
    return root


def find_blocks(node: Block, header: str) -> list[Block]:
    """Tous les blocs `config <header>` de l'arbre (récursif)."""
    out = []
    if node.kind == "config" and node.header == header:
        out.append(node)
    for c in node.children:
        out.extend(find_blocks(c, header))
    return out


def _edit_children(block: Block) -> list[Block]:
    return [c for c in block.children if c.kind == "edit"]


def parse_header_user(text: str) -> str:
    """Extrait `user=` de l'en-tête #config-version (qui a sauvegardé la config)."""
    m = re.search(r"#config-version=[^\n]*?:user=([^\s:]+)", text)
    return m.group(1) if m else ""


def audit_config(text: str, cfg: dict, source_file: str = "", boitier: str = "inconnu") -> list[dict]:
    """Applique la grille d'audit et renvoie une liste de constats (dicts)."""
    root = parse_config(text)
    admins = set(cfg.get("admins_connus", []))
    _pats = [p.replace("(?i)", "") for p in cfg.get("comptes_suspects_regex", [])]
    rogue_re = re.compile("|".join(f"(?:{p})" for p in _pats), re.IGNORECASE) if _pats else None

    findings: list[dict] = []

    def add(regle, severite, detail):
        findings.append({"boitier": boitier, "source_file": source_file,
                         "regle": regle, "severite": severite, "detail": detail})

    # --- Comptes admin (local + sso-admin) ---
    admin_blocks = find_blocks(root, "system admin") + find_blocks(root, "system sso-admin")
    for blk in admin_blocks:
        for adm in _edit_children(blk):
            nom = adm.name
            prof = adm.settings.get("accprofile", "").strip('"')
            # C1 — hors référentiel
            if nom not in admins:
                add("Compte admin hors référentiel (config) — SUSPICION", "critique",
                    f"admin={nom} profil={prof or '?'}")
            # C3 — nom voyou (motif)
            if rogue_re is not None and rogue_re.search(nom):
                add("Nom de compte admin potentiellement voyou (config) — SUSPICION", "eleve",
                    f"admin={nom}")
            # C2 — pas de trusted-host (joignable de partout)
            has_th = any(k.startswith("trusthost") for k in adm.settings)
            if not has_th:
                add("Compte admin sans restriction trusted-host", "eleve",
                    f"admin={nom} (aucun trusthost -> joignable de toute IP)")

    # Comptes SSO FortiCloud : listés en contexte (auto-provisionnés), signalés
    # seulement si le nom est inattendu (motif voyou).
    for blk in find_blocks(root, "system sso-fortigate-cloud-admin"):
        for adm in _edit_children(blk):
            if not _CLOUD_ACCOUNT_RE.search(adm.name) and rogue_re is not None \
                    and rogue_re.search(adm.name):
                add("Compte SSO cloud au nom inhabituel — SUSPICION", "eleve",
                    f"sso-cloud-admin={adm.name}")

    # --- C4 : Automation à action sensible (persistance/exfil) ---
    for blk in find_blocks(root, "system automation-action"):
        for act in _edit_children(blk):
            at = act.settings.get("action-type", "").strip('"')
            if at in SENSITIVE_AUTOMATION:
                add("Automation à action sensible (persistance/exfil possible)", "eleve",
                    f"action={act.name} type={at}")

    # --- C5 : Accès admin exposé (telnet partout ; http/ssh sur interface WAN) ---
    for blk in find_blocks(root, "system interface"):
        for itf in _edit_children(blk):
            acc = itf.settings.get("allowaccess", "")
            role = itf.settings.get("role", "").strip('"')
            services = set(acc.split())
            if "telnet" in services:
                add("Accès admin TELNET activé sur une interface (clair, non chiffré)", "eleve",
                    f"interface={itf.name} allowaccess={acc}")
            if role == "wan" and ({"http", "https", "ssh"} & services):
                add("Accès admin (GUI/SSH) exposé sur interface WAN", "eleve",
                    f"interface={itf.name} role=wan allowaccess={acc}")

    # --- C6 : Config sauvegardée par un compte hors référentiel ---
    saver = parse_header_user(text)
    if saver and saver not in admins:
        add("Configuration sauvegardée par un compte hors référentiel — SUSPICION", "moyen",
            f"user={saver}")

    return findings


def audit_files(conf_paths, cfg: dict, boitier_map=None) -> pd.DataFrame:
    """Audite plusieurs fichiers .conf -> DataFrame triée par sévérité.
    boitier_map(source_file) -> boitier (optionnel)."""
    from pathlib import Path
    rows = []
    for p in conf_paths:
        p = Path(p)
        text = p.read_text(errors="replace")
        boitier = boitier_map(p.name) if boitier_map else "inconnu"
        rows.extend(audit_config(text, cfg, source_file=p.name, boitier=boitier))
    cols = ["boitier", "source_file", "severite", "regle", "detail"]
    if not rows:
        return pd.DataFrame(columns=cols)
    df = pd.DataFrame(rows)
    df["sev_rank"] = df["severite"].map(SEV_ORDER).fillna(0).astype(int)
    return df.sort_values("sev_rank", ascending=False)[cols + ["sev_rank"]].reset_index(drop=True)
