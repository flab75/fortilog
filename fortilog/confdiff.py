"""Comparaison de deux configurations FortiGate (.conf) : un état VALIDÉ/de référence
vs un état ACTUEL (potentiellement corrompu). Répond à :
- QU'EST-CE QUI A CHANGÉ : objets ajoutés / supprimés / modifiés (admins, règles,
  VPN, interfaces, routes, automation, DNS, users…), avec le détail des attributs.
- PAR QUI / QUAND : attribution via les LOGS (`logdesc="Object attribute configured"`
  → `user` / `action` / `time`). Le `.conf` seul ne porte pas cette info (sauf qui a
  *sauvegardé* le backup, en-tête `user=`). Hors fenêtre de logs → « inconnu ».

Garde-fou : on décrit des écarts de configuration ; un changement légitime n'est pas
une compromission. Attribution = lecture directe des logs, jamais inventée.
"""
from __future__ import annotations
import re
import pandas as pd

from .confaudit import parse_config, find_blocks, parse_header_user

SEV_ORDER = {"info": 0, "faible": 1, "moyen": 2, "eleve": 3, "critique": 4}

# Sections « sensibles » (préfixes de header `config …`) — signal sur le bruit
# (on ignore par défaut les gui-dashboard et cosmétiques). `all_sections=True` lève le filtre.
SECURITY_PREFIXES = (
    "system admin", "system sso-admin", "system sso-fortigate-cloud-admin",
    "system api-user", "system accprofile", "system global", "system interface",
    "system dns", "system automation-action", "system automation-stitch",
    "system automation-trigger", "system ha", "system fortiguard",
    "firewall policy", "firewall address", "firewall addrgrp", "firewall vip",
    "firewall service custom", "firewall ssl-ssh-profile",
    "vpn ipsec phase1-interface", "vpn ipsec phase2-interface",
    "vpn ssl settings", "vpn ssl web portal",
    "router static", "router policy",
    "user local", "user group", "user ldap", "user radius", "user peer",
)

# Clés dont la valeur ne doit pas être affichée (hashs / secrets) — recherche en sous-chaîne.
_SECRET_KEYS = re.compile(r"(password|passwd|psksecret|ppk-secret|secret|private-key|auth-pwd)", re.I)


def _all_headers(node, acc):
    if node.kind == "config":
        acc.add(node.header)
    for c in node.children:
        _all_headers(c, acc)


def _section_objects(root, header):
    """(objets edit -> settings, settings directs du bloc) pour un header donné."""
    objs, direct = {}, {}
    for blk in find_blocks(root, header):
        direct.update(blk.settings)
        for e in blk.children:
            if e.kind == "edit":
                objs[e.name] = dict(e.settings)
    return objs, direct


def _fmt_val(key, val):
    return "(valeur masquée)" if _SECRET_KEYS.search(key) else val


def _settings_changes(old: dict, new: dict) -> str:
    parts = []
    for k in sorted(set(old) | set(new)):
        ov, nv = old.get(k), new.get(k)
        if ov == nv:
            continue
        if ov is None:
            parts.append(f"+{k}={_fmt_val(k, nv)}")
        elif nv is None:
            parts.append(f"-{k}")
        else:
            parts.append(f"{k}: {_fmt_val(k, ov)} → {_fmt_val(k, nv)}")
    return " ; ".join(parts)


def _criticite(header: str, statut: str) -> str:
    if header.startswith(("system admin", "system sso", "system api-user")):
        return "critique" if statut in ("AJOUTÉ", "SUPPRIMÉ") else "eleve"
    if header.startswith("system automation"):
        return "eleve"
    if header.startswith(("firewall policy", "vpn ", "router ", "user ")):
        return "eleve" if statut in ("AJOUTÉ", "SUPPRIMÉ") else "moyen"
    if header.startswith(("system global", "system dns", "system interface")):
        return "moyen"
    return "faible"


def diff_configs(text_ok: str, text_current: str, all_sections: bool = False) -> pd.DataFrame:
    """Compare deux .conf. Renvoie une table des écarts (section, objet, statut, détail)."""
    ra, rb = parse_config(text_ok), parse_config(text_current)
    headers: set = set()
    _all_headers(ra, headers)
    _all_headers(rb, headers)
    if not all_sections:
        headers = {h for h in headers if h.startswith(SECURITY_PREFIXES)}

    rows = []
    for header in sorted(headers):
        oa, da = _section_objects(ra, header)
        ob, db = _section_objects(rb, header)
        # objets (edit)
        for name in sorted(set(oa) | set(ob)):
            if name in ob and name not in oa:
                rows.append((header, name, "AJOUTÉ", _settings_changes({}, ob[name])))
            elif name in oa and name not in ob:
                rows.append((header, name, "SUPPRIMÉ", ""))
            elif oa[name] != ob[name]:
                rows.append((header, name, "MODIFIÉ", _settings_changes(oa[name], ob[name])))
        # paramètres directs du bloc (ex. system global / dns)
        if da != db:
            ch = _settings_changes(da, db)
            if ch:
                rows.append((header, "(paramètres)", "MODIFIÉ", ch))

    cols = ["section", "objet", "statut", "changements"]
    if not rows:
        return pd.DataFrame(columns=cols + ["criticite"])
    df = pd.DataFrame(rows, columns=cols)
    df["criticite"] = [_criticite(h, s) for h, s in zip(df["section"], df["statut"])]
    df["_rank"] = df["criticite"].map(SEV_ORDER).fillna(0).astype(int)
    return df.sort_values(["_rank", "section"], ascending=[False, True]).drop(columns="_rank").reset_index(drop=True)


def load_change_events(logs_dir, cfg=None) -> pd.DataFrame:
    """Charge depuis les logs les événements de changement de config (objet + auteur + date)."""
    from .main import load_file
    from . import ingest, normalize
    parts = []
    for f in ingest.list_log_files(logs_dir):
        parts.append(load_file(f))
    cols = ["timestamp", "user", "action", "cfgpath", "cfgobj", "ui"]
    if not parts:
        return pd.DataFrame(columns=cols)
    full = pd.concat(parts, ignore_index=True)
    full["timestamp"] = normalize.build_timestamp(full)
    g = lambda c: full.get(c, pd.Series([""] * len(full))).fillna("").astype(str)
    mask = g("cfgobj").ne("") & g("cfgpath").ne("")
    out = full.loc[mask, [c for c in cols if c in full.columns]].copy()
    return out


def attribute_changes(diff_df: pd.DataFrame, change_events: pd.DataFrame) -> pd.DataFrame:
    """Ajoute auteur / quand / action_log à chaque écart, par corrélation avec les logs."""
    df = diff_df.copy()
    df["auteur"], df["quand"], df["action_log"] = "", "", ""
    if df.empty:
        return df
    if change_events is None or change_events.empty:
        df["auteur"] = "inconnu (pas de logs)"
        return df
    ce = change_events.copy()
    ce["cfgobj"] = ce["cfgobj"].astype(str)
    for i, r in df.iterrows():
        if r["objet"] == "(paramètres)":
            df.at[i, "auteur"] = "voir events « Configuration changed »"
            continue
        token = str(r["section"]).split()[-1]  # ex. "admin" pour "system admin"
        m = ce[ce["cfgobj"] == r["objet"]]
        if "cfgpath" in m.columns and not m.empty:
            narrowed = m[m["cfgpath"].astype(str).str.split(".").str[-1] == token]
            if not narrowed.empty:
                m = narrowed
        m = m.dropna(subset=["timestamp"]) if "timestamp" in m.columns else m
        if not m.empty and "timestamp" in m.columns and m["timestamp"].notna().any():
            last = m.loc[m["timestamp"].idxmax()]
            df.at[i, "auteur"] = str(last.get("user", ""))
            df.at[i, "quand"] = str(last.get("timestamp", ""))[:19]
            df.at[i, "action_log"] = str(last.get("action", ""))
        else:
            df.at[i, "auteur"] = "inconnu (hors fenêtre de logs)"
    return df


def compare(ok_path, current_path, logs_dir=None, cfg=None, all_sections=False):
    """Compare deux fichiers .conf (+ attribution via logs si fournis).
    Renvoie (diff_df, meta) avec qui a sauvegardé chaque backup."""
    from pathlib import Path
    text_ok = Path(ok_path).read_text(errors="replace")
    text_cur = Path(current_path).read_text(errors="replace")
    diff = diff_configs(text_ok, text_cur, all_sections=all_sections)
    if logs_dir:
        diff = attribute_changes(diff, load_change_events(logs_dir, cfg))
    else:
        diff = attribute_changes(diff, pd.DataFrame())
    meta = {
        "ok_file": Path(ok_path).name, "current_file": Path(current_path).name,
        "ok_saved_by": parse_header_user(text_ok), "current_saved_by": parse_header_user(text_cur),
        "n_changes": len(diff),
    }
    return diff, meta


def main():
    import argparse
    import yaml
    from pathlib import Path
    ap = argparse.ArgumentParser(description="Comparer deux configurations FortiGate (.conf)")
    ap.add_argument("ok", help="config de référence / validée")
    ap.add_argument("current", help="config actuelle / à vérifier")
    ap.add_argument("--logs", help="dossier de logs pour l'attribution (qui/quand)")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--all", action="store_true", help="toutes les sections (pas seulement sensibles)")
    a = ap.parse_args()
    cfg = yaml.safe_load(Path(a.config).read_text()) if Path(a.config).exists() else {}
    diff, meta = compare(a.ok, a.current, logs_dir=a.logs, cfg=cfg, all_sections=a.all)
    print(f"Référence : {meta['ok_file']} (sauvée par {meta['ok_saved_by'] or '?'})")
    print(f"Actuelle  : {meta['current_file']} (sauvée par {meta['current_saved_by'] or '?'})")
    print(f"Écarts : {meta['n_changes']}\n")
    if diff.empty:
        print("Aucun écart sur les sections analysées.")
    else:
        with pd.option_context("display.max_colwidth", 80, "display.width", 200):
            print(diff.to_string(index=False))


if __name__ == "__main__":
    main()
