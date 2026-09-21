# SPDX-License-Identifier: AGPL-3.0-or-later
"""Grappes d'IP CANDIDATES à un blocage — liste de travail, jamais un ordre.

L'outil ne bloque rien et ne décide rien : il isole les IP dont le comportement,
DANS LES LOGS FOURNIS, n'a pas d'explication légitime, et les regroupe comme on les
bloquerait réellement (un objet /24 plutôt que quarante objets hôte).

Trois critères cumulatifs, tous vérifiables ligne à ligne :
  1. IP EXTERNE et hors infrastructure connue (WAN/mgmt, peers IPsec, DNS légitimes) ;
  2. a tenté au moins `seuil_comptes_inexistants` comptes ABSENTS du référentiel —
     comportement qu'aucun utilisateur légitime n'a (mesuré : une IP d'attaque en tente
     65 à 640, un utilisateur qui se trompe de mot de passe en tente UN) ;
  3. ZÉRO session réussie sur toute la période. C'est le garde-fou anti-coupure : on ne
     propose jamais de bloquer une IP depuis laquelle quelqu'un a ouvert une session.

Regroupement en /24 — MAIS si ce /24 contient par ailleurs une IP ayant réussi une
connexion, le /24 n'est PAS proposé : chaque IP coupable y reste en /32. Bloquer le
préfixe couperait l'utilisateur légitime.

Le regroupement par similarité de dictionnaire (Jaccard sur les identifiants tentés) a
été essayé et ÉCARTÉ : mesuré sur de vrais logs, les bots d'une même campagne SE
PARTAGENT le dictionnaire (J≈0.01 entre deux IP voisines du même /24 tapant 635 comptes
chacune). Il aurait vu quarante campagnes distinctes là où il y en a deux.
"""
from __future__ import annotations
import ipaddress
import pandas as pd

from . import geo
from .common import FAIL_LOGDESC, str_col

NOTE = "candidat — décision humaine, l'outil ne bloque rien"

COLS = ["grappe", "n_ip", "ips", "pays", "asn", "org", "reputation",
        "n_echecs", "n_comptes_inexistants", "cadence_mediane_s",
        "premiere_vue", "derniere_vue", "verification", "note"]

SUCCES_LOGDESC = ("Admin login successful", "SSL VPN tunnel up")


def _known_users(cfg: dict) -> set:
    """Comptes du référentiel (même source que R16), en minuscules."""
    admins = set(cfg.get("admins_connus", []))
    vpn = set(cfg.get("utilisateurs_vpn_actifs", []))
    locaux = set(sum((cfg.get("utilisateurs_locaux") or {}).values(), []))
    return {str(u).lower() for u in (admins | vpn | locaux)}


def _prefix24(ip: str) -> str:
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return ""


def build_candidats(full: pd.DataFrame, cfg: dict, enricher=None, repdb=None) -> pd.DataFrame:
    if full is None or full.empty or "srcip" not in full.columns:
        return pd.DataFrame(columns=COLS)
    par = cfg.get("blocage_candidats") or {}
    if not par.get("actif", True):
        return pd.DataFrame(columns=COLS)
    seuil = int(par.get("seuil_comptes_inexistants", 5))
    maxi = int(par.get("max_grappes", 50))

    ld = str_col(full, "logdesc")
    srcip = str_col(full, "srcip")
    user = str_col(full, "user").str.lower()

    # (3) IP ayant réussi une connexion : exclues, et leur /24 aussi (anti-coupure).
    succes_ips = set(srcip[ld.isin(SUCCES_LOGDESC) & srcip.ne("")].unique())
    prefixes_proteges = {_prefix24(ip) for ip in succes_ips} - {""}

    fail = ld.isin(FAIL_LOGDESC) & srcip.ne("") & user.ne("")
    if not fail.any():
        return pd.DataFrame(columns=COLS)

    # (1) externes, hors infrastructure connue
    nets = geo._nets(cfg)
    infra = geo._infra_ips(cfg)
    fdf = pd.DataFrame({"ip": srcip[fail], "u": user[fail],
                        "t": full.loc[fail, "timestamp"] if "timestamp" in full.columns else pd.NaT})
    fdf = fdf[~fdf["ip"].isin(infra) & ~fdf["ip"].isin(succes_ips)]
    if fdf.empty:
        return pd.DataFrame(columns=COLS)
    portee = {ip: geo.classify_scope(ip, nets) for ip in fdf["ip"].unique()}
    fdf = fdf[fdf["ip"].map(portee).eq(geo.EXTERNE)]
    if fdf.empty:
        return pd.DataFrame(columns=COLS)

    # (2) comptes tentés ABSENTS du référentiel
    connus = _known_users(cfg)
    inexistants = fdf[~fdf["u"].isin(connus)].groupby("ip")["u"].nunique()
    coupables = set(inexistants[inexistants >= seuil].index)
    if not coupables:
        return pd.DataFrame(columns=COLS)

    cdf = fdf[fdf["ip"].isin(coupables)]
    if enricher is None:
        enricher = geo.load_enricher(cfg)
    if repdb is None:
        repdb = geo.load_reputation(cfg)

    # Grappe = /24, sauf si ce /24 abrite une IP ayant réussi -> l'IP reste en /32.
    def _grappe(ip):
        p = _prefix24(ip)
        return p if (p and p not in prefixes_proteges) else f"{ip}/32"

    cdf = cdf.assign(grappe=cdf["ip"].map(_grappe))
    rows = []
    for grappe, g in cdf.groupby("grappe"):
        ips = sorted(set(g["ip"]))
        infos = [enricher.lookup(ip) or {} for ip in ips]
        def _top(champ):
            vals = [str(i.get(champ, "")) for i in infos if i.get(champ)]
            return pd.Series(vals).mode().iat[0] if vals else ""
        rep = sorted({n for ip in ips for n in (repdb.match(ip) if repdb else [])})
        ts = pd.to_datetime(g["t"], errors="coerce").dropna().sort_values()
        cadence = float(ts.diff().dt.total_seconds().median()) if len(ts) > 2 else float("nan")
        rows.append({
            "grappe": grappe, "n_ip": len(ips),
            "ips": ", ".join(ips[:20]) + (f" … (+{len(ips) - 20})" if len(ips) > 20 else ""),
            "pays": _top("pays"), "asn": _top("asn"), "org": _top("org"),
            "reputation": ", ".join(rep),
            "n_echecs": len(g),
            "n_comptes_inexistants": int(g[~g["u"].isin(connus)]["u"].nunique()),
            "cadence_mediane_s": round(cadence, 1) if cadence == cadence else "",
            "premiere_vue": ts.iloc[0] if len(ts) else pd.NaT,
            "derniere_vue": ts.iloc[-1] if len(ts) else pd.NaT,
            "verification": "aucune session réussie depuis cette grappe sur la période",
            "note": NOTE,
        })
    out = pd.DataFrame(rows, columns=COLS)
    return out.sort_values("n_echecs", ascending=False).head(maxi).reset_index(drop=True)


def cli_brouillon(candidats: pd.DataFrame, cfg: dict | None = None) -> str:
    """BROUILLON de configuration FortiGate à RELIRE avant de coller.

    Ne fabrique que des objets et une règle de blocage ; aucun secret, aucune suppression.
    `set action deny` est posé EXPLICITEMENT : sans lui, la règle peut rester sans effet
    et FortiOS ne l'affiche pas dans `show` (cf. constat C10)."""
    if candidats is None or candidats.empty:
        return ""
    par = (cfg or {}).get("blocage_candidats") or {}
    groupe = str(par.get("nom_groupe", "BLOCKLIST-FORTILOG"))
    intf = str(par.get("interface_wan", "wan1"))
    noms = []
    L = ["# ---------------------------------------------------------------------------",
         "# BROUILLON À RELIRE — généré depuis les logs, à valider avant de coller.",
         "# Vérifier une par une les grappes proposées : un /24 peut abriter un futur",
         f"# utilisateur légitime. Adapter le nom d'interface (« {intf} ») à ce boîtier.",
         "# ---------------------------------------------------------------------------",
         "config firewall address"]
    for _, r in candidats.iterrows():
        net = str(r["grappe"])
        nom = f"BLK-{net.replace('/', '-')}"
        noms.append(nom)
        try:
            n = ipaddress.ip_network(net)
            subnet = f"{n.network_address} {n.netmask}"
        except ValueError:
            continue
        L += [f'    edit "{nom}"',
              f"        set subnet {subnet}",
              f'        set comment "{r["n_echecs"]} échecs, {r["n_comptes_inexistants"]} '
              f'comptes inexistants, aucune session réussie"',
              "    next"]
    L += ["end", "config firewall addrgrp", f'    edit "{groupe}"',
          "        set member " + " ".join(f'"{n}"' for n in noms), "    next", "end",
          "# Si un groupe de blocage existe déjà (ex. BLOCKLIST-VPN), ajouter plutôt les",
          f"# membres ci-dessus à celui-là que de créer « {groupe} ».",
          "config firewall local-in-policy", "    edit 0",
          f'        set intf "{intf}"', f'        set srcaddr "{groupe}"',
          '        set dstaddr "all"', '        set service "ALL"',
          '        set schedule "always"',
          "        set action deny   # EXPLICITE : sans cette ligne la règle peut rester "
          "sans effet (cf. constat C10)",
          "    next", "end",
          "# Pour pouvoir VÉRIFIER que le blocage agit, journaliser les refus :",
          "config log setting", "    set local-in-deny-unicast enable", "end"]
    return "\n".join(L)
