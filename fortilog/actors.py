# SPDX-License-Identifier: AGPL-3.0-or-later
"""Acteurs à risque + frise chronologique.

- `build_actors` : agrège les événements par IP source EXTERNE et par compte, avec un
  score de PRIORISATION transparent. Le score sert à TRIER les entités à investiguer,
  jamais à conclure (principe directeur : l'outil signale, le verdict reste humain).

      score = poids.critique×n_critique + poids.eleve×n_eleve + poids.moyen×n_moyen
            + poids.faible×n_faible + poids.reputation×(réputation non vide)
            + poids.regle_supplementaire×(nb règles distinctes − 1)

  Pondérations dans config.yaml (`acteurs.poids`), défauts : critique=100, eleve=30,
  moyen=10, faible=3, reputation=50, regle_supplementaire=20.

- `build_timeline` : événements de sévérité ≥ `timeline.severite_min` (défaut eleve)
  triés chronologiquement, rafales consécutives de même (règle, acteur) dans la même
  heure résumées en une ligne (le compte exact n'est jamais perdu).
"""
from __future__ import annotations
import pandas as pd

from .common import SEV_ORDER, str_col
from .geo import _infra_ips, _nets, classify_scope, EXTERNE

SCORE_COL = "score_priorisation (tri, pas un verdict)"
POIDS_DEFAUT = {"critique": 100, "eleve": 30, "moyen": 10, "faible": 3,
                "reputation": 50, "regle_supplementaire": 20}
SEVERITES = ("critique", "eleve", "moyen", "faible", "info")

ACTOR_COLS = ["acteur_type", "acteur", SCORE_COL, "severite_max",
              "n_critique", "n_eleve", "n_moyen", "n_faible", "n_info",
              "nb_regles", "echecs_login", "premiere_vue", "derniere_vue",
              "pays", "asn", "org", "reputation", "boitiers"]

TIMELINE_COLS = ["timestamp", "boitier", "severite", "regle", "acteur", "detail"]


def _fails_by(full, col: str) -> dict:
    """Volume d'échecs de login admin par valeur de `col` dans les données complètes."""
    if full is None or full.empty or col not in full.columns:
        return {}
    m = str_col(full, "logdesc").eq("Admin login failed")
    if not m.any():
        return {}
    return str_col(full, col)[m].value_counts().to_dict()


def _first_nonempty(s) -> str:
    return next((v for v in s if v), "")


def _ts(events) -> pd.Series:
    """Colonne timestamp en datetime (NaT si absente), toujours une série alignée."""
    if "timestamp" not in events.columns:
        return pd.Series(pd.NaT, index=events.index)
    return pd.to_datetime(events["timestamp"], errors="coerce")


def _aggregate_axis(events, key: pd.Series, acteur_type: str, fails_map: dict,
                    poids: dict) -> pd.DataFrame:
    """Agrège les événements par acteur (`key` = série des identifiants, '' = ignoré)."""
    is_ip = acteur_type == "ip"
    d = pd.DataFrame({
        "acteur": key,
        "severite": str_col(events, "severite"),
        "regle": str_col(events, "regle"),
        "boitier": str_col(events, "boitier"),
        "timestamp": _ts(events),
        "pays": str_col(events, "srcip_pays") if is_ip else "",
        "asn": str_col(events, "srcip_asn") if is_ip else "",
        "org": str_col(events, "srcip_org") if is_ip else "",
        "reputation": str_col(events, "srcip_reputation") if is_ip else "",
    }, index=events.index)
    # une même ligne peut être signalée par plusieurs règles -> index dupliqué : on aplatit
    d = d[d["acteur"].ne("")].reset_index(drop=True)
    if d.empty:
        return pd.DataFrame(columns=ACTOR_COLS)

    g = d.groupby("acteur")
    base = g.agg(nb_regles=("regle", "nunique"),
                 premiere_vue=("timestamp", "min"),
                 derniere_vue=("timestamp", "max"),
                 pays=("pays", _first_nonempty),
                 asn=("asn", _first_nonempty),
                 org=("org", _first_nonempty),
                 reputation=("reputation", _first_nonempty),
                 boitiers=("boitier", lambda s: ", ".join(sorted({b for b in s if b}))))
    sev = pd.crosstab(d["acteur"], d["severite"])
    for k in SEVERITES:
        base[f"n_{k}"] = sev[k].reindex(base.index).fillna(0).astype(int) if k in sev.columns else 0
    sev_max = pd.Series("", index=base.index)
    for k in reversed(SEVERITES):  # info -> critique : le plus sévère présent gagne
        sev_max = sev_max.mask(base[f"n_{k}"] > 0, k)
    base["severite_max"] = sev_max
    base["echecs_login"] = base.index.map(lambda a: int(fails_map.get(a, 0)))
    base[SCORE_COL] = (
        poids["critique"] * base["n_critique"] + poids["eleve"] * base["n_eleve"]
        + poids["moyen"] * base["n_moyen"] + poids["faible"] * base["n_faible"]
        + poids["reputation"] * base["reputation"].ne("").astype(int)
        + poids["regle_supplementaire"] * (base["nb_regles"] - 1).clip(lower=0))
    base["acteur_type"] = acteur_type
    return base.reset_index()[ACTOR_COLS]


def build_actors(events, full, meta, cfg) -> pd.DataFrame:
    """Table « Acteurs à risque » : IP externes et comptes vus dans les événements,
    triés par score de priorisation décroissant, top `acteurs.max_lignes` (défaut 100).
    Les IP d'infrastructure connue (WAN/mgmt des boîtiers, peers/DNS) sont exclues."""
    if events is None or events.empty:
        return pd.DataFrame(columns=ACTOR_COLS)
    acfg = cfg.get("acteurs") or {}
    poids = {**POIDS_DEFAUT, **(acfg.get("poids") or {})}
    max_lignes = int(acfg.get("max_lignes", 100))

    srcip = str_col(events, "srcip")
    if "srcip_portee" in events.columns:
        portee = str_col(events, "srcip_portee")
    else:  # événements non enrichis : portée recalculée (aucune base requise)
        nets = _nets(cfg)
        portee = srcip.map(lambda ip: classify_scope(ip, nets) if ip else "")
    infra = _infra_ips(cfg)
    ip_key = srcip.where(portee.eq(EXTERNE) & ~srcip.isin(infra), "")

    out = pd.concat([
        _aggregate_axis(events, ip_key, "ip", _fails_by(full, "srcip"), poids),
        _aggregate_axis(events, str_col(events, "user"), "compte",
                        _fails_by(full, "user"), poids),
    ], ignore_index=True)
    if out.empty:
        return pd.DataFrame(columns=ACTOR_COLS)
    return (out.sort_values([SCORE_COL, "acteur"], ascending=[False, True])
               .head(max_lignes).reset_index(drop=True))


def build_timeline(events, cfg) -> pd.DataFrame:
    """Frise chronologique des événements de sévérité ≥ `timeline.severite_min`
    (défaut eleve). Rafale = plus de `timeline.max_par_groupe` (défaut 3) événements
    CONSÉCUTIFS de même (règle, acteur) dans la même heure -> une seule ligne
    « × N similaires de HH:MM à HH:MM » (le compte exact est conservé)."""
    tcfg = cfg.get("timeline") or {}
    sev_min = SEV_ORDER.get(str(tcfg.get("severite_min", "eleve")), 3)
    max_grp = int(tcfg.get("max_par_groupe", 3))
    if events is None or events.empty:
        return pd.DataFrame(columns=TIMELINE_COLS)

    ts = _ts(events)
    keep = str_col(events, "severite").map(SEV_ORDER).fillna(-1).ge(sev_min) & ts.notna()
    if not keep.any():
        return pd.DataFrame(columns=TIMELINE_COLS)
    user, srcip = str_col(events, "user"), str_col(events, "srcip")
    d = pd.DataFrame({
        "timestamp": ts, "boitier": str_col(events, "boitier"),
        "severite": str_col(events, "severite"), "regle": str_col(events, "regle"),
        "acteur": user.where(user.ne(""), srcip),
        "detail": str_col(events, "detail"),
    })[keep].sort_values("timestamp")

    key = d["regle"] + "\x00" + d["acteur"]
    hour = d["timestamp"].dt.floor("h")
    grp_id = (key.ne(key.shift()) | hour.ne(hour.shift())).cumsum()
    rows = []
    for _, grp in d.groupby(grp_id, sort=False):
        if len(grp) > max_grp:
            r = grp.iloc[0].copy()
            t0, t1 = grp["timestamp"].iloc[0], grp["timestamp"].iloc[-1]
            r["detail"] = f"× {len(grp)} similaires de {t0:%H:%M} à {t1:%H:%M}"
            rows.append(r)
        else:
            rows.extend(r for _, r in grp.iterrows())
    return pd.DataFrame(rows, columns=TIMELINE_COLS).reset_index(drop=True)
