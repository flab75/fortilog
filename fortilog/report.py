# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rapport texte synthétique. Rappelle les limites assumées."""
from __future__ import annotations
import pandas as pd

from . import logguide
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
        if f.get("doublon_de"):
            L.append(f"  - {f['name']}: IDENTIQUE à {f['doublon_de']} (contenu MD5 égal) "
                     "— ignoré, ce n'est pas une seconde source")
            continue
        fenetre = (f" | couvre {f['debut']} -> {f['fin']}"
                   if f.get("debut") else " | fenêtre inconnue (aucun horodatage exploitable)")
        L.append(f"  - {f['name']}: type={f['type']}/{f['subtype']} {label} "
                 f"| {f['rows']} lignes{fenetre}")
    L.append("  (Une absence d'événement ne vaut que DANS ces fenêtres : un log qui s'arrête "
             "à 13:34 ne dit rien de 13:40.)")
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
    vs = tables.get("vpn_sessions")
    st_ = meta.get("vpn_stats") or {}
    if vs is not None and not vs.empty:
        L.append(f"SESSIONS VPN : {st_.get('n_sessions', len(vs))} tunnel(s) "
                 f"pour {st_.get('n_users', 0)} compte(s)")
        if st_.get("motifs"):
            L.append("  Motifs de clôture : "
                     + ", ".join(f"{k} ({v})" for k, v in st_["motifs"].items()))
        if st_.get("n_ouvertes"):
            L.append(f"  {st_['n_ouvertes']} session(s) encore ouverte(s) en fin de période "
                     "(durée non close : pas de tunnel down dans la fenêtre).")
        if st_.get("n_orphelines"):
            L.append(f"  {st_['n_orphelines']} session(s) montée(s) avant la période analysée.")
        for _, r in vs.iterrows():
            deb = str(r["debut"])[:16] if pd.notna(r["debut"]) else "?"
            fin = str(r["fin"])[:16] if pd.notna(r["fin"]) else "—"
            geo = f" {r['pays']}" if r.get("pays") else ""
            L.append(f"    {deb} -> {fin} | {r['boitier']} | {r['user']} ({r['groupe']}) "
                     f"| {r['srcip']}{geo} | {r['duree']} | {r['statut']}"
                     + (f" : {r['motif_fin']}" if r["motif_fin"] else "")
                     + f" | ↑{r['envoye_mo']} ↓{r['recu_mo']} Mo | {r['legitimite']}")
        L.append(f"  (Hors sessions : {st_.get('n_login_fail', 0)} échec(s) de login SSL-VPN et "
                 f"{st_.get('n_bruit_tls', 0)} ligne(s) de bruit TLS sans utilisateur — "
                 "poignées de main de scanners, pas des connexions.)")
        L.append("")
    bl = tables.get("blocages_local_in")
    if bl is not None and not bl.empty:
        L.append("EFFICACITÉ DES BLOCAGES LOCAL-IN (descriptif, sans sévérité) :")
        for _, r in bl.iterrows():
            L.append(f"  {r['srcip']} [{r['boitiers']}] — {r['n_drops']} drop(s) — {r['statut']}")
        L.append("  (Fenêtre = celle des logs fournis. Si les drops local-in ne sont pas "
                 "journalisés sur le boîtier, l'absence de ligne ne prouve rien.)")
        L.append("")
    emp = tables.get("empreintes_ip")
    if emp is not None and not emp.empty:
        L.append("EMPREINTE DE DICTIONNAIRE ET CADENCE PAR IP (descriptif, sans sévérité) :")
        for _, r in emp.iterrows():
            L.append(f"    {r['srcip']} — {r['n_tentatives']} tentatives sur "
                     f"{r['n_comptes']} identifiant(s) : {r['echantillon_comptes']}")
            cad = (f"toutes les ~{r['cadence_mediane_s']} s ({r['regularite']})"
                   if r["cadence_mediane_s"] != "" else "cadence non mesurable")
            L.append(f"        {cad}" + (f" — {r['suite']}" if r["suite"] else ""))
        L.append("  (Le vocabulaire tenté caractérise la campagne ; l'outil ne la nomme pas. "
                 "La colonne « suite » extrapole la CADENCE : soit quand guetter la "
                 "prochaine tentative, soit depuis quand l'IP s'est tue — une observation "
                 "à confronter aux contre-mesures, pas une preuve qu'elles en sont la cause.)")
        L.append("")
    rs = tables.get("reseau_descriptif")
    if rs is not None and not rs.empty:
        L.append("BRUIT RÉSEAU ENTRANT (descriptif, sans sévérité) :")
        for sujet, g in rs.groupby("sujet", sort=False):
            f0 = g.iloc[0]
            L.append(f"  {sujet} — {f0['n_lignes_sujet']} ligne(s) depuis "
                     f"{f0['n_sources_sujet']} source(s) ; {len(g)} listée(s) ici "
                     "(les plus volumineuses) :")
            for _, r in g.iterrows():
                geo_ = f" [{r['pays']} / {r['asn']} {r['org']}]" if r["pays"] or r["asn"] else ""
                L.append(f"    {r['source']}{geo_} — {r['detail'] or str(r['occurrences'])}")
        L.append("  (Ce que les logs montrent, sans qualification : ni « scan », ni « attaque ». "
                 "L'ICMP est reconnu par le champ app=PING du boîtier ; un export où il est "
                 "vide ne remonte rien.)")
        L.append("")
    bc = tables.get("blocage_candidats")
    if bc is not None and not bc.empty:
        L.append(f"GRAPPES D'IP CANDIDATES À UN BLOCAGE : {len(bc)} (liste de travail, "
                 "l'outil ne bloque rien — décision humaine)")
        for _, r in bc.iterrows():
            L.append(f"    {r['grappe']} ({r['n_ip']} IP) "
                     + (f"[{r['pays']} / {r['asn']} {r['org']}] " if r["pays"] or r["asn"] else "")
                     + f": {r['n_echecs']} échecs, {r['n_comptes_inexistants']} comptes "
                     f"inexistants tentés — {r['verification']}"
                     + (f" — réputation: {r['reputation']}" if r["reputation"] else ""))
        L.append("  (Critères : IP externe hors infrastructure, ≥ N comptes inexistants tentés, "
                 "AUCUNE session réussie sur la période. Un /24 abritant une IP ayant réussi "
                 "une connexion n'est jamais proposé en bloc.)")
        if meta.get("blocage_cli"):
            L.append("")
            L.append("  --- BROUILLON DE CONFIGURATION À RELIRE (ne pas coller tel quel) ---")
            for line in meta["blocage_cli"].split("\n"):
                L.append("  " + line)
        L.append("")
    ud = tables.get("utm_descriptifs")
    if ud is not None and not ud.empty:
        L.append("AGRÉGATS DESCRIPTIFS UTM (sans règle d'alerte) :")
        for subtype, grp in ud.groupby("type_utm"):
            L.append(f"  utm/{subtype} — {grp['libelle'].iloc[0]} :")
            for _, r in grp.iterrows():
                L.append(f"    {r['valeur']} : {r['occurrences']} {r['note']}")
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
    L.append(logguide.guide_markdown(meta.get("files")).replace("**", "").replace("# ", ""))
    L.append("")
    L.append(LIMITES)
    return "\n".join(L)
