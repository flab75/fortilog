# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rapport d'analyse SYNTHÉTIQUE : décrit les résultats, explique les problèmes
potentiels ou avérés, et relie les constats entre eux (config ↔ logs ↔ threat intel).

Distingue explicitement :
- [AVÉRÉ]      : fait lisible directement (état de config, volume de logs) ;
- [À CONFIRMER]: suspicion (compte hors référentiel, chaîne corrélée, nom voyou…).

Ne conclut JAMAIS à une compromission que les données ne prouvent pas — conforme
au principe directeur (l'outil signale, le verdict reste humain).
"""
from __future__ import annotations
import pandas as pd

import datetime as _dt

from .common import SEV_ORDER
from .actors import POIDS_DEFAUT, SCORE_COL, build_timeline


def _sev_counts(df):
    if df is None or df.empty or "severite" not in df.columns:
        return {}
    return df["severite"].value_counts().to_dict()


def _hors_acquittes(df):
    """Lignes hors constats acquittés : exclues du DÉCOMPTE d'alerte uniquement —
    elles restent signalées partout avec leur tag [ACQUITTÉ le …]."""
    if df is None or df.empty or "suivi" not in df.columns:
        return df
    return df[df["suivi"] != "acquitte"]


def _period(tables):
    agg = tables.get("agg")
    if agg is not None and not agg.empty and "bucket" in agg.columns:
        b = pd.to_datetime(agg["bucket"], errors="coerce").dropna()
        if len(b):
            return f"{b.min().date()} → {b.max().date()}"
    return "n/d"


def _config_tag(regle) -> str:
    """[À CONFIRMER] pour les constats de SUSPICION (compte hors référentiel, nom voyou,
    SSO cloud inhabituel…) ; [AVÉRÉ] pour les états de configuration factuels."""
    s = str(regle)
    if "SUSPICION" in s or "hors référentiel" in s or "voyou" in s:
        return "[À CONFIRMER]"
    return "[AVÉRÉ]"


def _geo_str(r) -> str:
    """Résumé géo/ASN d'une ligne IP (pays / ASN org), '?' si pays inconnu."""
    pays = str(r.get("srcip_pays") or "").strip() or "?"
    asn = str(r.get("srcip_asn") or "").strip()
    org = str(r.get("srcip_org") or "").strip()
    return pays + (f" / AS{asn}" + (f" {org}" if org else "") if asn else "")


def _ip_line(r) -> str:
    """Ligne synthétique pour une IP source (géo + volume + logins échoués)."""
    occ = int(r.get("occurrences", 0) or 0)
    fails = int(r.get("logins_echoues", 0) or 0)
    return f"{r.get('srcip','')} — {_geo_str(r)} — {occ:,} occ., {fails:,} login(s) échoué(s)"


def _max_constats(cfg) -> int:
    """Nombre de constats/lignes détaillés par section (config.yaml `rapport.max_constats`, défaut 5)."""
    try:
        return max(1, int((cfg.get("rapport") or {}).get("max_constats", 5)))
    except (ValueError, TypeError):
        return 5


def build_analysis(tables, meta, cfg) -> str:
    events = tables.get("events")
    ca = tables.get("config_audit")
    chains = tables.get("chains")
    rep = tables.get("reputation")
    se = tables.get("sources_externes")
    agg = tables.get("agg")
    bursts = tables.get("bursts")
    max_constats = _max_constats(cfg)
    L: list[str] = []

    def h(t): L.append(t); L.append("")

    h("# RAPPORT D'ANALYSE — SYNTHÈSE")
    L.append("> L'outil **signale et structure** ; le **verdict reste humain**. "
             "[AVÉRÉ] = fait constaté ; [À CONFIRMER] = suspicion à valider hors logs.")
    L.append("")

    # Suivi entre analyses : quoi de neuf depuis la dernière fois (si état antérieur)
    sv = meta.get("suivi") or {}
    if sv.get("warning"):
        L.append(f"⚠ Suivi entre analyses indisponible : {sv['warning']}.")
        L.append("")
    elif sv.get("anterieur") and sv.get("date_precedente"):
        try:
            dp = _dt.date.fromisoformat(sv["date_precedente"]).strftime("%d/%m/%Y")
        except ValueError:
            dp = sv["date_precedente"]
        acq = (f" {sv['n_acquittes']} constat(s) acquitté(s), signalés mais exclus "
               f"du décompte d'alerte." if sv.get("n_acquittes") else "")
        L.append(f"**{sv.get('n_constats', 0)} constat(s) dont "
                 f"{sv.get('n_nouveaux', 0)} NOUVEAU(X) depuis l'analyse du {dp}.**{acq}")
        L.append("")

    # Fraîcheur des bases hors-ligne (géo/ASN/réputation) : jamais bloquant
    for b in meta.get("bases") or []:
        if b["perime"]:
            L.append(f"⚠ La base « {b['nom']} » a {b['age_jours']} jours — "
                     f"les correspondances peuvent être obsolètes.")
    if any(b["perime"] for b in meta.get("bases") or []):
        L.append("")

    # 1. Périmètre
    h("## 1. Périmètre analysé")
    L.append(f"- Logs : {meta.get('n_files', 0)} fichier(s), "
             f"{meta.get('n_rows', 0):,} lignes ({meta.get('dedup', 0):,} doublons retirés).")
    if meta.get("n_configs"):
        L.append(f"- Configurations FortiGate (.conf) : {meta['n_configs']} fichier(s).")
    L.append(f"- Période couverte : {_period(tables)}.")
    boites = []
    if events is not None and not events.empty and "boitier" in events.columns:
        boites = [b for b in events["boitier"].unique().tolist() if b]
    if boites:
        L.append(f"- Boîtiers identifiés : {', '.join(map(str, boites))}.")
        if "inconnu" in boites:
            L.append("  - ⚠ Des événements sont rattachés à « inconnu » : fichiers sans IP "
                     "WAN/mgmt du boîtier et sans indice de nom (ex. app-ctrl). Pour un "
                     "rattachement complet, utiliser le référentiel aux vraies IP (config.local.yaml).")
    L.append("")

    # 2. État de la configuration (AVÉRÉ)
    h("## 2. État de la configuration (.conf) — [AVÉRÉ sauf mention]")
    if ca is None or ca.empty:
        L.append("- Aucun fichier de configuration importé (ou aucun constat).")
    else:
        ca_actifs = _hors_acquittes(ca)
        sc = _sev_counts(ca_actifs)
        ligne = ", ".join(f"{k}={sc[k]}" for k in ["critique", "eleve", "moyen", "faible", "info"] if k in sc)
        n_acq = len(ca) - len(ca_actifs)
        acq_txt = f" + {n_acq} acquitté(s) hors décompte" if n_acq else ""
        L.append(f"- {len(ca_actifs)} constat(s) d'audit sur {meta.get('n_configs', 0)} "
                 f"configuration(s) ({ligne}){acq_txt}.")
        # Constats groupés par type de règle ; SOUS chaque règle, ses constats
        # individuels détaillés (jusqu'à max_constats). Règles ordonnées par sévérité
        # max décroissante puis par volume.
        L.append(f"- Par type de constat (jusqu'à {max_constats} détaillé(s) par type) :")
        ranked = (ca.assign(_r=ca["severite"].map(SEV_ORDER).fillna(0))
                    .groupby("regle")
                    .agg(n=("regle", "size"), rmax=("_r", "max"))
                    .sort_values(["rmax", "n"], ascending=[False, False]))
        for regle, row in ranked.iterrows():
            n = int(row["n"])
            L.append(f"  - {_config_tag(regle)} {regle} — {n} constat(s).")
            for i, (_, r) in enumerate(ca[ca["regle"] == regle].head(max_constats).iterrows(), 1):
                detail = str(r.get("detail", "") or "").strip()
                boit = f" ({r['boitier']})" if r.get("boitier") else ""
                L.append(f"    {i}. {detail}{boit}.")
            if n > max_constats:
                L.append(f"    (… et {n - max_constats} autre(s) — voir la feuille « Audit config ».)")
        # explications ciblées
        joined = " ".join(ca["regle"].tolist())
        if "WAN" in joined:
            L.append("  → L'interface d'administration (GUI/SSH) est **joignable depuis Internet** : "
                     "surface d'attaque directe, cohérente avec un volume de brute-force élevé.")
        if "trusted-host" in joined:
            L.append("  → Des comptes admin **acceptent une connexion depuis n'importe quelle IP** "
                     "(pas de restriction trusted-host) — durcissement recommandé.")
        if "hors référentiel" in joined:
            L.append("  → Un compte admin **absent du référentiel** est présent : à vérifier en IAM "
                     "(peut être un ajout légitime récent — À CONFIRMER, pas une preuve).")
    L.append("")

    # 2bis. Changements de configuration vs référence
    cd = tables.get("config_diff")
    if cd is not None and not cd.empty:
        ref = meta.get("config_ref") or "config de référence"
        h(f"## 2bis. Changements de configuration vs {ref} — [À CONFIRMER]")
        cc = cd["criticite"].value_counts().to_dict()
        ligne = ", ".join(f"{k}={cc[k]}" for k in ["critique", "eleve", "moyen", "faible", "info"] if k in cc)
        L.append(f"- {len(cd)} écart(s) de configuration ({ligne}).")
        prio = cd[cd["criticite"].isin(["critique", "eleve"])]
        for _, r in prio.head(12).iterrows():
            who = ""
            if r.get("auteur"):
                who = f" — par **{r['auteur']}**" + (f" le {r['quand']}" if r.get("quand") else "")
            L.append(f"  - [{r['statut']}] `{r['section']}` / `{r['objet']}`{who}.")
        added_admins = cd[(cd["statut"] == "AJOUTÉ") & cd["section"].str.startswith("system admin")]
        if not added_admins.empty:
            L.append(f"  → ⚠ {len(added_admins)} **compte(s) admin ajouté(s)** : vérifier qu'ils sont "
                     "légitimes (présents au référentiel, créés par un admin connu).")
        L.append("  (Un changement légitime n'est pas une compromission — à confirmer.)")
        L.append("")

    # 3. Activité dans les logs
    h("## 3. Activité observée dans les logs")
    if events is None or events.empty:
        L.append("- Aucun log analysé.")
    else:
        ev_actifs = _hors_acquittes(events)
        sc = _sev_counts(ev_actifs)
        ligne = ", ".join(f"{k}={sc[k]}" for k in ["critique", "eleve", "moyen", "faible", "info"] if k in sc)
        n_acq = len(events) - len(ev_actifs)
        acq_txt = f" + {n_acq} acquitté(s) hors décompte" if n_acq else ""
        L.append(f"- Événements signalés : {len(ev_actifs)} ({ligne}){acq_txt}.")
        # événements individuels les plus sévères (table déjà triée par sévérité décroissante)
        n_show = min(len(events), max_constats)
        if n_show and "regle" in events.columns:
            L.append(f"- Événements les plus sévères ({n_show} sur {len(events)}) :")
            for i, (_, r) in enumerate(events.head(n_show).iterrows(), 1):
                ts = str(r.get("timestamp", "") or "")[:19]
                detail = str(r.get("detail", "") or "").strip()
                detail = f" — {detail}" if detail else ""
                boit = f" ({r['boitier']})" if r.get("boitier") else ""
                head = f"{ts} · " if ts else ""
                L.append(f"  {i}. {head}{r.get('severite', '')} · {r.get('regle', '')}{detail}{boit}.")
        if agg is not None and not agg.empty and "echecs_login" in agg.columns:
            tot_fail = int(agg["echecs_login"].sum())
            tot_ok = int(agg["logins_ok"].sum()) if "logins_ok" in agg.columns else 0
            L.append(f"- [AVÉRÉ] Authentification admin : {tot_fail:,} échecs de login, "
                     f"{tot_ok} login(s) réussi(s) sur la période.")
        # Brute-force réussi (R11)
        r11 = events[events["regle"].str.contains("potentiellement réussi|après rafale", na=False)] \
            if "regle" in events.columns else events.iloc[0:0]
        if not r11.empty:
            L.append(f"- ⚠ [À CONFIRMER] {len(r11)} **brute-force potentiellement réussi** "
                     "(succès précédé d'une rafale d'échecs) — à valider d'urgence.")
        else:
            L.append("- [AVÉRÉ] **Aucun brute-force réussi détecté** : aucun succès admin précédé "
                     "d'une rafale d'échecs (le volume d'attaque n'a pas abouti dans les logs fournis).")
        if bursts is not None and not bursts.empty:
            L.append(f"- {len(bursts)} rafale(s) d'activité détectée(s) (pics au-dessus du seuil adaptatif).")
        if chains is not None and not chains.empty:
            L.append(f"- ⚠ [À CONFIRMER] {len(chains)} chaîne(s) IoC corrélée(s) "
                     "(accès → compte → exfiltration) — corrélation temporelle, pas une preuve.")
        else:
            L.append("- Aucune chaîne IoC (accès → compte → exfiltration) corrélée.")
    L.append("")

    # 3bis. Acteurs à investiguer en priorité (score de tri transparent, pas un verdict)
    act = tables.get("acteurs")
    if act is not None and not act.empty:
        h("## 3bis. Acteurs à investiguer en priorité")
        L.append("- Le score sert à **trier** les entités à examiner, jamais à conclure "
                 "(pondérations : `acteurs.poids` du config.yaml).")
        poids = {**POIDS_DEFAUT, **((cfg.get("acteurs") or {}).get("poids") or {})}
        n_show = min(len(act), max_constats)
        L.append(f"- Top {n_show} (sur {len(act)}) :")
        for i, (_, r) in enumerate(act.head(n_show).iterrows(), 1):
            parts = []
            for k in ("critique", "eleve", "moyen", "faible"):
                n = int(r.get(f"n_{k}", 0) or 0)
                if n:
                    parts.append(f"{n}×{poids[k]} {k}")
            if str(r.get("reputation") or ""):
                parts.append(f"{poids['reputation']} réputation ({r['reputation']})")
            extra = int(r.get("nb_regles", 1) or 1) - 1
            if extra > 0:
                parts.append(f"{extra}×{poids['regle_supplementaire']} règle(s) suppl.")
            geo = ""
            if str(r.get("pays") or ""):
                geo = f" — {r['pays']}" + (f" / AS{r['asn']} {r.get('org', '')}".rstrip()
                                           if str(r.get("asn") or "") else "")
            fails = int(r.get("echecs_login", 0) or 0)
            fail_txt = f" — {fails:,} échec(s) de login" if fails else ""
            L.append(f"  {i}. [{r['acteur_type']}] **{r['acteur']}** — "
                     f"score {int(r[SCORE_COL])} ({' + '.join(parts)}){geo}{fail_txt}.")
        L.append("")

    # 3ter. Frise chronologique (P1b) — événements les plus sévères dans l'ordre
    tl = build_timeline(events, cfg) if events is not None else pd.DataFrame()
    if not tl.empty:
        sev_min = (cfg.get("timeline") or {}).get("severite_min", "eleve")
        h(f"## 3ter. FRISE CHRONOLOGIQUE (événements ≥ {sev_min}, rafales regroupées)")
        for _, r in tl.iterrows():
            detail = str(r.get("detail", "") or "").strip()
            line = (f"- {r['timestamp']:%d/%m %H:%M} [{str(r['severite']).upper()}] "
                    f"{r['regle']} — {r['acteur']}")
            L.append(line + (f" — {detail}" if detail else "") + ".")
        L.append("")

    # 4. Origine des accès externes
    h("## 4. Origine des accès externes (géo / threat intel)")
    if se is not None and not se.empty:
        L.append(f"- {len(se)} IP source externe(s) classées par volume.")
        n_show = min(len(se), max_constats)
        L.append(f"  - Top {n_show} :")
        for i, (_, r) in enumerate(se.head(n_show).iterrows(), 1):
            L.append(f"    {i}. {_ip_line(r)}.")
    if rep is not None and not rep.empty:
        L.append(f"- ⚠ [AVÉRÉ] {len(rep)} IP ayant touché le pare-feu sont présentes dans une "
                 "**liste de réputation** (IP déjà connues malveillantes). Présence = signal fort, "
                 "À CONFIRMER (listes parfois larges).")
        n_show = min(len(rep), max_constats)
        L.append(f"  - {n_show} première(s) :")
        for i, (_, r) in enumerate(rep.head(n_show).iterrows(), 1):
            listes = str(r.get("listes", "") or "")
            L.append(f"    {i}. {_ip_line(r)} — listes : {listes}.")
    if (se is None or se.empty) and (rep is None or rep.empty):
        L.append("- Pas d'enrichissement disponible (ni sources externes, ni listes de réputation).")
    if not meta.get("geo_available", False):
        L.append("- Détection *impossible travel* (comptes admin) indisponible : pas de base géo locale.")
    L.append("")

    # 5. Lecture d'ensemble
    h("## 5. Lecture d'ensemble")
    wan = ca is not None and not ca.empty and ca["regle"].str.contains("WAN").any()
    big_bf = agg is not None and not agg.empty and "echecs_login" in agg.columns and int(agg["echecs_login"].sum()) > 1000
    known_bad = rep is not None and not rep.empty
    breach = events is not None and not events.empty and "regle" in events.columns and \
        events["regle"].str.contains("potentiellement réussi", na=False).any()
    if wan and big_bf:
        msg = ("- La **GUI d'administration exposée sur WAN** explique le **volume massif de "
               "brute-force** observé dans les logs")
        if known_bad:
            msg += ", majoritairement depuis des **IP déjà connues malveillantes**"
        msg += "."
        L.append(msg)
    if big_bf and not breach:
        L.append("- **Aucune compromission avérée** à ce stade : malgré l'attaque, aucun accès "
                 "réussi corrélé. La menace est sur la **surface d'attaque**, pas (encore) sur un accès obtenu.")
    if breach:
        L.append("- ⚠ Signal de **brute-force possiblement abouti** — priorité de vérification (IAM, "
                 "sessions actives, changements de config récents).")
    if not (wan or big_bf or known_bad or breach):
        L.append("- Pas de corrélation forte entre les constats sur ce jeu de données.")
    L.append("")

    # 6. À confirmer hors logs
    h("## 6. À confirmer (hors périmètre des logs)")
    L.append("- Comptes admin hors référentiel : valider via l'IAM FortiCloud / la gestion des accès.")
    L.append("- Chaînes IoC et brute-force « réussi » : corrélations temporelles, pas des preuves.")
    L.append("- Listes de réputation : vérifier que l'IP n'est pas un faux positif (CGNAT, cloud partagé).")
    L.append("")
    L.append("— Fin de la synthèse. Détails par catégorie dans les autres feuilles / sections.")
    return "\n".join(L)
