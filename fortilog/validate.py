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

    # Brute-force réussi (R11, section optionnelle) : fenêtre + seuil entiers > 0
    bf = cfg.get("bruteforce")
    if bf is not None:
        if not isinstance(bf, dict):
            errors.append(f"bruteforce : attendu un dictionnaire, reçu {type(bf).__name__}")
        else:
            for k in ("fenetre_minutes", "seuil_echecs"):
                v = bf.get(k)
                if v is not None:
                    try:
                        if int(v) <= 0:
                            errors.append(f"bruteforce.{k} : doit être > 0, reçu {v}")
                    except (ValueError, TypeError):
                        errors.append(f"bruteforce.{k} : '{v}' n'est pas un entier valide")

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
