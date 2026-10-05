# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validation du config.yaml au démarrage. Échoue proprement sur référentiel mal formé."""
from __future__ import annotations
import ipaddress
import re

REQUIRED_KEYS = [
    "boitiers", "admins_connus", "plages_internes",
    "destinations_legitimes", "rafales",
]

REQUIRED_RAFALES = ["fenetre_minutes", "facteur_mediane", "mode_seuil"]


class ConfigError(Exception):
    pass


def validate_config(cfg: dict) -> list[str]:
    """Valide la configuration et renvoie la liste des erreurs (vide = OK)."""
    errors: list[str] = []

    if not isinstance(cfg, dict):
        return ["Le fichier config ne contient pas un dictionnaire YAML valide."]

    for key in REQUIRED_KEYS:
        if key not in cfg:
            errors.append(f"Clé requise manquante : '{key}'")

    # Boîtiers : chaque entrée doit avoir wan ou mgmt
    boitiers = cfg.get("boitiers", {})
    if isinstance(boitiers, dict):
        for name, ips in boitiers.items():
            if not isinstance(ips, dict):
                errors.append(f"boitiers.{name} : attendu un dictionnaire (wan/mgmt), reçu {type(ips).__name__}")
                continue
            for field in ("wan", "mgmt"):
                val = ips.get(field)
                if val is not None:
                    try:
                        ipaddress.ip_address(str(val))
                    except ValueError:
                        errors.append(f"boitiers.{name}.{field} : '{val}' n'est pas une adresse IP valide")

    # Plages internes : CIDR valides
    plages = cfg.get("plages_internes", [])
    if isinstance(plages, list):
        for i, cidr in enumerate(plages):
            cidr_clean = str(cidr).split("#")[0].strip()
            try:
                ipaddress.ip_network(cidr_clean)
            except ValueError:
                errors.append(f"plages_internes[{i}] : '{cidr}' n'est pas un CIDR valide")

    # Pool VPN (optionnel, R9 ; défaut 10.212.134.0/24) : un CIDR ou une liste de CIDR
    pool = cfg.get("pool_vpn")
    if pool is not None:
        entries = [pool] if isinstance(pool, str) else pool
        if not isinstance(entries, list):
            errors.append(f"pool_vpn : attendu un CIDR ou une liste de CIDR, reçu {type(pool).__name__}")
        else:
            for i, cidr in enumerate(entries):
                try:
                    ipaddress.ip_network(str(cidr).split("#")[0].strip())
                except ValueError:
                    errors.append(f"pool_vpn[{i}] : '{cidr}' n'est pas un CIDR valide")

    # Destinations légitimes : IP valides
    dests = cfg.get("destinations_legitimes", {})
    if isinstance(dests, dict):
        for group, ips in dests.items():
            if not isinstance(ips, list):
                errors.append(f"destinations_legitimes.{group} : attendu une liste, reçu {type(ips).__name__}")
                continue
            for j, ip in enumerate(ips):
                try:
                    ipaddress.ip_address(str(ip))
                except ValueError:
                    try:
                        ipaddress.ip_network(str(ip), strict=False)
                    except ValueError:
                        errors.append(f"destinations_legitimes.{group}[{j}] : '{ip}' n'est pas une IP ni un CIDR valide")

    # Regex de comptes suspects : compilables
    patterns = cfg.get("comptes_suspects_regex", [])
    if isinstance(patterns, list):
        for i, pat in enumerate(patterns):
            try:
                re.compile(pat)
            except re.error as e:
                errors.append(f"comptes_suspects_regex[{i}] : regex invalide '{pat}' — {e}")

    # Rafales : clés et types numériques
    rafales = cfg.get("rafales", {})
    if isinstance(rafales, dict):
        for key in REQUIRED_RAFALES:
            if key not in rafales:
                errors.append(f"rafales.{key} : clé requise manquante")
        fw = rafales.get("fenetre_minutes")
        if fw is not None:
            try:
                v = int(fw)
                if v <= 0:
                    errors.append(f"rafales.fenetre_minutes : doit être > 0, reçu {v}")
            except (ValueError, TypeError):
                errors.append(f"rafales.fenetre_minutes : '{fw}' n'est pas un entier valide")
        fm = rafales.get("facteur_mediane")
        if fm is not None:
            try:
                v = float(fm)
                if v <= 0:
                    errors.append(f"rafales.facteur_mediane : doit être > 0, reçu {v}")
            except (ValueError, TypeError):
                errors.append(f"rafales.facteur_mediane : '{fm}' n'est pas un nombre valide")
        ms = rafales.get("mode_seuil")
        if ms is not None and ms not in ("adaptatif", "fixe"):
            errors.append(f"rafales.mode_seuil : '{ms}' invalide, attendu 'adaptatif' ou 'fixe'")

    # Admins connus : doit être une liste
    admins = cfg.get("admins_connus")
    if admins is not None and not isinstance(admins, list):
        errors.append(f"admins_connus : attendu une liste, reçu {type(admins).__name__}")

    # Enrichissement géo (optionnel) : chemins = chaînes ; top = entier > 0.
    # Base absente sur le disque = NON bloquant (dégradation honnête à l'exécution).
    for k in ("geo_db_path", "asn_db_path"):
        v = cfg.get(k)
        if v is not None and not isinstance(v, str):
            errors.append(f"{k} : attendu un chemin (chaîne) ou null, reçu {type(v).__name__}")
    top = cfg.get("top_sources_externes")
    if top is not None:
        try:
            if int(top) <= 0:
                errors.append(f"top_sources_externes : doit être > 0, reçu {top}")
        except (ValueError, TypeError):
            errors.append(f"top_sources_externes : '{top}' n'est pas un entier valide")

    # Listes de réputation (optionnelles) : liste d'entrées {nom, path} ou de chemins.
    # Fichier absent = NON bloquant (dégradation honnête à l'exécution).
    rl = cfg.get("reputation_lists")
    if rl is not None:
        if not isinstance(rl, list):
            errors.append(f"reputation_lists : attendu une liste, reçu {type(rl).__name__}")
        else:
            for i, entry in enumerate(rl):
                if isinstance(entry, dict):
                    if not entry.get("path"):
                        errors.append(f"reputation_lists[{i}] : clé 'path' requise")
                    url = entry.get("url")
                    if url is not None and not (isinstance(url, str)
                                                and url.startswith(("http://", "https://"))):
                        errors.append(f"reputation_lists[{i}].url : attendu une URL http(s), reçu {url!r}")
                elif not isinstance(entry, str):
                    errors.append(f"reputation_lists[{i}] : attendu {{nom, path}} ou un chemin, "
                                  f"reçu {type(entry).__name__}")

    # Liste blanche app-ctrl (optionnelle) : doit être une liste de chaînes
    wl = cfg.get("app_ctrl_whitelist")
    if wl is not None:
        if not isinstance(wl, list):
            errors.append(f"app_ctrl_whitelist : attendu une liste, reçu {type(wl).__name__}")
        else:
            for i, entry in enumerate(wl):
                if not isinstance(entry, str):
                    errors.append(f"app_ctrl_whitelist[{i}] : attendu une chaîne, reçu {type(entry).__name__}")

    # Brute-force R11 + rafales name_invalid R13 (sections optionnelles) :
    # fenêtre + seuil entiers > 0
    for section in ("bruteforce", "bruteforce_name_invalid"):
        bf = cfg.get(section)
        if bf is not None:
            if not isinstance(bf, dict):
                errors.append(f"{section} : attendu un dictionnaire, reçu {type(bf).__name__}")
            else:
                for k in ("fenetre_minutes", "seuil_echecs"):
                    v = bf.get(k)
                    if v is not None:
                        try:
                            if int(v) <= 0:
                                errors.append(f"{section}.{k} : doit être > 0, reçu {v}")
                        except (ValueError, TypeError):
                            errors.append(f"{section}.{k} : '{v}' n'est pas un entier valide")

    # Comptes ciblés (R16, section optionnelle) : actif booléen, seuils entiers > 0
    cc = cfg.get("comptes_cibles")
    if cc is not None:
        if not isinstance(cc, dict):
            errors.append(f"comptes_cibles : attendu un dictionnaire, reçu {type(cc).__name__}")
        else:
            if cc.get("actif") is not None and not isinstance(cc.get("actif"), bool):
                errors.append(f"comptes_cibles.actif : attendu un booléen, reçu {cc.get('actif')!r}")
            for k in ("seuil_spray", "seuil_ip_distinctes", "seuil_ip_campagne"):
                v = cc.get(k)
                if v is not None:
                    try:
                        if int(v) <= 0:
                            errors.append(f"comptes_cibles.{k} : doit être > 0, reçu {v}")
                    except (ValueError, TypeError):
                        errors.append(f"comptes_cibles.{k} : '{v}' n'est pas un entier valide")

    # Grappes candidates au blocage (section optionnelle) : actif booléen, seuils > 0
    bc = cfg.get("blocage_candidats")
    if bc is not None:
        if not isinstance(bc, dict):
            errors.append(f"blocage_candidats : attendu un dictionnaire, reçu {type(bc).__name__}")
        else:
            if bc.get("actif") is not None and not isinstance(bc.get("actif"), bool):
                errors.append(
                    f"blocage_candidats.actif : attendu un booléen, reçu {bc.get('actif')!r}")
            for k in ("seuil_comptes_inexistants", "max_grappes"):
                v = bc.get(k)
                if v is not None:
                    try:
                        if int(v) <= 0:
                            errors.append(f"blocage_candidats.{k} : doit être > 0, reçu {v}")
                    except (ValueError, TypeError):
                        errors.append(f"blocage_candidats.{k} : '{v}' n'est pas un entier valide")

    # Empreintes/cadence (section optionnelle) : actif booléen, seuils > 0
    em = cfg.get("empreintes")
    if em is not None:
        if not isinstance(em, dict):
            errors.append(f"empreintes : attendu un dictionnaire, reçu {type(em).__name__}")
        else:
            if em.get("actif") is not None and not isinstance(em.get("actif"), bool):
                errors.append(f"empreintes.actif : attendu un booléen, reçu {em.get('actif')!r}")
            for k in ("min_tentatives", "max_lignes"):
                v = em.get(k)
                if v is not None:
                    try:
                        if int(v) <= 0:
                            errors.append(f"empreintes.{k} : doit être > 0, reçu {v}")
                    except (ValueError, TypeError):
                        errors.append(f"empreintes.{k} : '{v}' n'est pas un entier valide")

    # Bruit réseau descriptif (section optionnelle) : actif booléen, top_n > 0
    rs = cfg.get("reseau_descriptif")
    if rs is not None:
        if not isinstance(rs, dict):
            errors.append(f"reseau_descriptif : attendu un dictionnaire, reçu {type(rs).__name__}")
        else:
            if rs.get("actif") is not None and not isinstance(rs.get("actif"), bool):
                errors.append(f"reseau_descriptif.actif : attendu un booléen, reçu {rs.get('actif')!r}")
            v = rs.get("top_n")
            if v is not None:
                try:
                    if int(v) <= 0:
                        errors.append(f"reseau_descriptif.top_n : doit être > 0, reçu {v}")
                except (ValueError, TypeError):
                    errors.append(f"reseau_descriptif.top_n : '{v}' n'est pas un entier valide")

    # Pays attendus (R17, clé optionnelle) : liste de codes ISO2
    pa = cfg.get("pays_attendus")
    if pa is not None:
        if not isinstance(pa, list):
            errors.append(f"pays_attendus : attendu une liste, reçu {type(pa).__name__}")
        else:
            for i, c in enumerate(pa):
                if not isinstance(c, str) or len(c) != 2 or not c.isalpha():
                    errors.append(f"pays_attendus[{i}] : attendu un code pays ISO2 "
                                  f"(ex. FR), reçu {c!r}")

    # Horaires ouvrés (R12, section optionnelle) : debut/fin entiers 0-23, debut < fin
    ho = cfg.get("horaires_ouvres")
    if ho is not None:
        if not isinstance(ho, dict):
            errors.append(f"horaires_ouvres : attendu un dictionnaire, reçu {type(ho).__name__}")
        else:
            hd, hf = ho.get("debut"), ho.get("fin")
            vals = {}
            for k, v in (("debut", hd), ("fin", hf)):
                if v is not None:
                    try:
                        iv = int(v)
                        if not (0 <= iv <= 23):
                            errors.append(f"horaires_ouvres.{k} : doit être entre 0 et 23, reçu {v}")
                        else:
                            vals[k] = iv
                    except (ValueError, TypeError):
                        errors.append(f"horaires_ouvres.{k} : '{v}' n'est pas un entier valide")
            if "debut" in vals and "fin" in vals and vals["debut"] >= vals["fin"]:
                errors.append(f"horaires_ouvres : debut ({vals['debut']}) doit être < fin ({vals['fin']})")

    # Nouveauté comportementale / impossible travel (R14/R15, section optionnelle)
    cp = cfg.get("comportement")
    if cp is not None:
        if not isinstance(cp, dict):
            errors.append(f"comportement : attendu un dictionnaire, reçu {type(cp).__name__}")
        else:
            fw_cp = cp.get("fenetre_minutes")
            if fw_cp is not None:
                try:
                    if int(fw_cp) <= 0:
                        errors.append(f"comportement.fenetre_minutes : doit être > 0, reçu {fw_cp}")
                except (ValueError, TypeError):
                    errors.append(f"comportement.fenetre_minutes : '{fw_cp}' n'est pas un entier valide")

    # Corrélation (section optionnelle) : fenêtre numérique, séquence = liste
    corr = cfg.get("correlation")
    if corr is not None:
        if not isinstance(corr, dict):
            errors.append(f"correlation : attendu un dictionnaire, reçu {type(corr).__name__}")
        else:
            fw = corr.get("fenetre_minutes")
            if fw is not None:
                try:
                    if int(fw) <= 0:
                        errors.append(f"correlation.fenetre_minutes : doit être > 0, reçu {fw}")
                except (ValueError, TypeError):
                    errors.append(f"correlation.fenetre_minutes : '{fw}' n'est pas un entier valide")
            seq = corr.get("sequence_requise")
            if seq is not None:
                if not isinstance(seq, list) or len(seq) < 2:
                    errors.append("correlation.sequence_requise : attendu une liste d'au moins 2 étapes")

    # Fraîcheur des bases (section optionnelle) : age_max_jours entier > 0
    bs = cfg.get("bases")
    if bs is not None:
        if not isinstance(bs, dict):
            errors.append(f"bases : attendu un dictionnaire, reçu {type(bs).__name__}")
        else:
            am = bs.get("age_max_jours")
            if am is not None:
                try:
                    if int(am) <= 0:
                        errors.append(f"bases.age_max_jours : doit être > 0, reçu {am}")
                except (ValueError, TypeError):
                    errors.append(f"bases.age_max_jours : '{am}' n'est pas un entier valide")
            mj = bs.get("maj")
            if mj is not None:
                if not isinstance(mj, dict):
                    errors.append(f"bases.maj : attendu un dictionnaire, reçu {type(mj).__name__}")
                else:
                    for k in ("reputation_jours", "asn_jours", "fortinet_jours", "timeout_s"):
                        v = mj.get(k)
                        if v is None:
                            continue
                        try:
                            if float(v) <= 0:
                                errors.append(f"bases.maj.{k} : doit être > 0, reçu {v}")
                        except (ValueError, TypeError):
                            errors.append(f"bases.maj.{k} : '{v}' n'est pas un nombre valide")

    # Agrégats descriptifs UTM (section optionnelle) : top_n entier > 0
    ud = cfg.get("utm_descriptif")
    if ud is not None:
        if not isinstance(ud, dict):
            errors.append(f"utm_descriptif : attendu un dictionnaire, reçu {type(ud).__name__}")
        else:
            tn = ud.get("top_n")
            if tn is not None:
                try:
                    if int(tn) <= 0:
                        errors.append(f"utm_descriptif.top_n : doit être > 0, reçu {tn}")
                except (ValueError, TypeError):
                    errors.append(f"utm_descriptif.top_n : '{tn}' n'est pas un entier valide")

    # Acteurs à risque (section optionnelle) : max_lignes entier > 0, poids numériques >= 0
    ac = cfg.get("acteurs")
    if ac is not None:
        if not isinstance(ac, dict):
            errors.append(f"acteurs : attendu un dictionnaire, reçu {type(ac).__name__}")
        else:
            ml = ac.get("max_lignes")
            if ml is not None:
                try:
                    if int(ml) <= 0:
                        errors.append(f"acteurs.max_lignes : doit être > 0, reçu {ml}")
                except (ValueError, TypeError):
                    errors.append(f"acteurs.max_lignes : '{ml}' n'est pas un entier valide")
            po = ac.get("poids")
            if po is not None:
                if not isinstance(po, dict):
                    errors.append(f"acteurs.poids : attendu un dictionnaire, reçu {type(po).__name__}")
                else:
                    for k, v in po.items():
                        try:
                            if float(v) < 0:
                                errors.append(f"acteurs.poids.{k} : doit être >= 0, reçu {v}")
                        except (ValueError, TypeError):
                            errors.append(f"acteurs.poids.{k} : '{v}' n'est pas un nombre valide")

    # Frise chronologique (section optionnelle) : sévérité connue, groupe entier > 0
    tl = cfg.get("timeline")
    if tl is not None:
        if not isinstance(tl, dict):
            errors.append(f"timeline : attendu un dictionnaire, reçu {type(tl).__name__}")
        else:
            sm = tl.get("severite_min")
            if sm is not None and sm not in ("info", "faible", "moyen", "eleve", "critique"):
                errors.append(f"timeline.severite_min : '{sm}' invalide "
                              f"(attendu info/faible/moyen/eleve/critique)")
            mg = tl.get("max_par_groupe")
            if mg is not None:
                try:
                    if int(mg) <= 0:
                        errors.append(f"timeline.max_par_groupe : doit être > 0, reçu {mg}")
                except (ValueError, TypeError):
                    errors.append(f"timeline.max_par_groupe : '{mg}' n'est pas un entier valide")

    # Rapport de synthèse (section optionnelle) : max_constats entier > 0
    rap = cfg.get("rapport")
    if rap is not None:
        if not isinstance(rap, dict):
            errors.append(f"rapport : attendu un dictionnaire, reçu {type(rap).__name__}")
        else:
            mc = rap.get("max_constats")
            if mc is not None:
                try:
                    if int(mc) <= 0:
                        errors.append(f"rapport.max_constats : doit être > 0, reçu {mc}")
                except (ValueError, TypeError):
                    errors.append(f"rapport.max_constats : '{mc}' n'est pas un entier valide")

    return errors


def coherence_referentiel(full, cfg, min_occ: int = 10) -> list[str]:
    """Le référentiel décrit-il bien CES logs ? Avertissements, jamais bloquant.

    Motivation (cas réel) : une analyse lancée avec le `config.yaml` anonymisé
    (`wan: 203.0.113.1`) sur de vrais logs → l'IP WAN réelle du pare-feu est inconnue,
    donc classée EXTERNE, absente des exclusions d'infrastructure, et le boîtier
    lui-même finit en tête des « acteurs à investiguer ».

    Heuristique, volontairement étroite : sur `traffic/local`, une interface de boîtier
    est la seule IP présente des DEUX côtés (`srcip` ET `dstip`, ≥ `min_occ` chacun).
    On ne conclut pas — on pose la question et on nomme l'IP à vérifier.
    """
    from . import geo
    from .common import str_col

    out: list[str] = []
    boitiers = cfg.get("boitiers") or {}
    declarees = {str(b.get(k)) for b in boitiers.values() for k in ("wan", "mgmt")
                 if b.get(k)}
    if full is None or full.empty or not declarees:
        return out

    src, dst = str_col(full, "srcip"), str_col(full, "dstip")
    vues = set(src[src.ne("")].unique()) | set(dst[dst.ne("")].unique())
    absentes = sorted(declarees - vues)
    if not absentes:
        return out

    loc = str_col(full, "type").eq("traffic") & str_col(full, "subtype").eq("local")
    ns, nd = src[loc].value_counts(), dst[loc].value_counts()
    nets = geo._nets(cfg)
    candidats = [ip for ip in (set(ns.index) & set(nd.index)) - declarees
                 if ip and ns[ip] >= min_occ and nd[ip] >= min_occ
                 and geo.classify_scope(ip, nets) == geo.EXTERNE]
    candidats.sort(key=lambda ip: -(int(ns[ip]) + int(nd[ip])))

    out.append("⚠ Référentiel : " + ", ".join(absentes)
               + (" est déclarée comme interface de boîtier mais n'apparaît"
                  if len(absentes) == 1 else
                  " sont déclarées comme interfaces de boîtier mais n'apparaissent")
               + " dans aucun log.")
    for ip in candidats[:3]:
        out.append(f"  {ip} se comporte comme une interface du boîtier "
                   f"(vue {int(ns[ip])} fois en source et {int(nd[ip])} fois en destination "
                   "sur traffic/local) — le référentiel ne correspond probablement pas à ces "
                   "logs, à vérifier. Tant qu'il n'est pas corrigé, cette IP est traitée comme "
                   "externe (classement des acteurs, géo, réputation).")
    if not candidats:
        out.append("  Aucune autre IP ne se comporte comme une interface du boîtier dans ces "
                   "logs — l'export ne couvre peut-être simplement pas ce boîtier.")
    return out
