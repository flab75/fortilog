"""Rapport texte synthétique. Rappelle les limites assumées."""
from __future__ import annotations
from .ingest import UTM_NO_RULES

LIMITES = """\
LIMITES ASSUMÉES :
- L'outil SIGNALE et structure ; le verdict reste humain.
- Analyse limitée aux fenêtres temporelles des fichiers fournis.
- Logs UTM présents seulement si les profils journalisent (absence != sécurité).
- Type de log inconnu : parsing générique + marquage, jamais d'analyse inventée.
- Comptes "voyous" détectés par motif = SUSPICION à confirmer (IAM FortiCloud / config).
- Chaînes suspectes = corrélation TEMPORELLE d'événements signalés, pas une preuve
  de compromission ; l'ordre + la fenêtre ne prouvent pas l'intention (à confirmer).
- Géo/ASN = contexte d'origine (base locale), ni preuve ni absolution ; qualité = celle
  de la base fournie ; sans base, seule la portée interne/externe est connue.
- IP en liste de réputation = signal fort mais À CONFIRMER : les listes peuvent être
  larges (CIDR entiers), datées ou inclure des IP partagées (CGNAT, cloud).
- Audit config (.conf) = constats sur l'état de la configuration (compte hors
  référentiel, admin sans trusted-host, accès exposé…) ; un compte récent légitime
  peut être hors référentiel — à confirmer, jamais une preuve de compromission."""


def build_report(tables, meta) -> str:
    L = []
    L.append("=" * 70)
    L.append("RAPPORT D'ANALYSE — LOGS FORTIGATE")
    L.append("=" * 70)
    L.append(f"Fichiers ingérés : {meta['n_files']} | lignes parsées : {meta['n_rows']} "
             f"| doublons retirés : {meta['dedup']}")
    fl = meta["files"]
    for f in fl:
        ts = (f['type'], f['subtype'])
        if not f['reconnu']:
            label = "(NON RECONNU -> grille générique)"
        elif ts in UTM_NO_RULES:
            label = "(UTM reconnu, sans règles dédiées — grille générique)"
        else:
            label = "(reconnu)"
        L.append(f"  - {f['name']}: type={f['type']}/{f['subtype']} {label} | {f['rows']} lignes")
    if meta.get("n_configs"):
        L.append(f"Fichiers de configuration audités (.conf) : {meta['n_configs']}")
    L.append("")
    ca = tables.get("config_audit")
    if ca is not None and not ca.empty:
        L.append(f"AUDIT CONFIGURATION (.conf) — constats : {len(ca)} (SUSPICION / à confirmer)")
        counts = ca["severite"].value_counts()
        for sev in ["critique", "eleve", "moyen", "faible", "info"]:
            if sev in counts:
                L.append(f"  {sev:9}: {counts[sev]}")
        for _, r in ca.iterrows():
            L.append(f"    [{r['severite']}] {r['boitier']} | {r['regle']} | {r['detail']}")
        L.append("")
    cd = tables.get("config_diff")
    if cd is not None and not cd.empty:
        ref = meta.get("config_ref") or "référence"
        L.append(f"CHANGEMENTS DE CONFIGURATION vs {ref} — {len(cd)} écart(s) (à confirmer) :")
        counts = cd["criticite"].value_counts()
        for sev in ["critique", "eleve", "moyen", "faible", "info"]:
            if sev in counts:
                L.append(f"  {sev:9}: {counts[sev]}")
        prio = cd[cd["criticite"].isin(["critique", "eleve"])]
        for _, r in prio.head(30).iterrows():
            who = f" | par {r['auteur']}" + (f" le {r['quand']}" if r.get("quand") else "") \
                if r.get("auteur") else ""
            L.append(f"    [{r['criticite']}] {r['statut']} {r['section']}/{r['objet']}"
                     f" | {str(r['changements'])[:60]}{who}")
        L.append("")
    agg = tables["agg"]
    if agg is not None and not agg.empty:
        L.append("AGRÉGATS PAR BOÎTIER / JOUR :")
        for _, r in agg.iterrows():
            L.append(f"  [{r['boitier']}] {str(r['bucket'])[:10]} : "
                     f"{r['echecs_login']} échecs, {r['logins_ok']} logins OK, "
                     f"{r['lockouts']} lockouts, {r['sslvpn_fails']} SSL-VPN fails, "
                     f"{r['pwd_invalid']} passwd_invalid, {r['ip_sources_uniques']} IP src")
        L.append("")
    ev = tables["events"]
    if ev is not None and not ev.empty:
        L.append(f"ÉVÉNEMENTS SIGNALÉS : {len(ev)}")
        counts = ev["severite"].value_counts()
        for sev in ["critique", "eleve", "moyen", "faible", "info"]:
            if sev in counts:
                L.append(f"  {sev:9}: {counts[sev]}")
        L.append("")
        crit = ev[ev["severite"].isin(["critique", "eleve"])]
        if not crit.empty:
            L.append("  Détail critique/élevé :")
            for _, r in crit.head(40).iterrows():
                ts = str(r.get("timestamp"))[:19]
                L.append(f"    [{r['severite']}] {ts} {r['boitier']} | {r['regle']} | {r['detail']}")
            L.append("")
    chains = tables.get("chains")
    if chains is not None and not chains.empty:
        L.append(f"CHAÎNES SUSPECTES (corrélation temporelle — À CONFIRMER) : {len(chains)}")
        for _, r in chains.iterrows():
            L.append(f"  [{r['severite']}] {str(r['debut'])[:19]} ({r['duree_min']} min) "
                     f"{r['boitier']} | {r['cle_type']}={r['cle']} | {r['etapes']}")
            L.append(f"      {r['detail']}")
        L.append("")
    diff = tables["diff"]
    if diff is not None and not diff.empty:
        al = diff[diff.get("alerte", False) == True]
        if not al.empty:
            L.append("DIFFÉRENTIELS — ALERTES (entités Prio 1 APPARUES) :")
            for _, r in al.iterrows():
                L.append(f"    {r['entite']}: '{r['valeur']}' apparu ({r['de']} -> {r['vers']})")
            L.append("")
    bursts = tables["bursts"]
    if bursts is not None and not bursts.empty:
        L.append(f"RAFALES DÉTECTÉES : {len(bursts)} (seuils adaptatifs)")
        L.append("")
    rep = tables.get("reputation")
    if rep is not None and not rep.empty:
        L.append(f"⚠ IP EN LISTE DE RÉPUTATION (threat intel — À CONFIRMER) : {len(rep)} IP")
        for _, r in rep.head(20).iterrows():
            loc = ""
            bits = [b for b in (r.get("srcip_pays", ""), r.get("srcip_asn", "")) if b]
            if bits:
                loc = " [" + " / ".join(bits) + "]"
            L.append(f"    {r['srcip']}{loc} — listes: {r['listes']} — "
                     f"{r['occurrences']} occ. ({r['logins_echoues']} logins échoués)")
        L.append("  (Présence en liste = signal fort, pas une preuve ; listes parfois larges.)")
        L.append("")
    se = tables.get("sources_externes")
    if se is not None and not se.empty:
        geo_on = meta.get("geo_available", False)
        suffix = "" if geo_on else " (géo/ASN indisponible — pas de base locale)"
        L.append(f"TOP SOURCES EXTERNES (contexte{suffix}) : {len(se)} IP")
        for _, r in se.head(15).iterrows():
            loc = ""
            if geo_on:
                bits = [b for b in (r.get("srcip_pays", ""), r.get("srcip_asn", ""),
                                    r.get("srcip_org", "")) if b]
                loc = (" [" + " / ".join(bits) + "]") if bits else ""
            L.append(f"    {r['srcip']}{loc} : {r['occurrences']} occ. "
                     f"({r['logins_echoues']} logins échoués)")
        L.append("  (Contexte d'origine des accès externes — ni preuve ni absolution.)")
        L.append("")
    sr = tables.get("security_rating")
    if sr is not None and not sr.empty:
        L.append("BILAN HARDENING (security-rating FortiGate) :")
        for _, r in sr.iterrows():
            ts_str = str(r.get("timestamp", ""))[:19]
            rtype = r.get("auditreporttype", "")
            score = r.get("auditscore", "?")
            c_crit = r.get("criticalcount", "?")
            c_high = r.get("highcount", "?")
            L.append(f"  [{ts_str}] {rtype} score={score} critical={c_crit} high={c_high}")
        L.append("  (Security Rating = audit de durcissement, pas une détection de compromission)")
        L.append("")
    L.append(LIMITES)
    return "\n".join(L)
