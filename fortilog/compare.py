"""Comparaison : agrégats temporels, détection de rafales adaptatives, différentiel d'entités."""
from __future__ import annotations
import pandas as pd


def aggregate(df: pd.DataFrame, bucket: str = "day") -> pd.DataFrame:
    freq = {"day": "D", "hour": "h"}.get(bucket, "D")
    d = df.dropna(subset=["timestamp"]).copy()
    d["bucket"] = d["timestamp"].dt.floor(freq)
    ld = d.get("logdesc", pd.Series("", index=d.index)).fillna("")
    rs = d.get("reason", pd.Series("", index=d.index)).fillna("")
    d["echec_login"] = (ld == "Admin login failed").astype(int)
    d["login_ok"] = (ld == "Admin login successful").astype(int)
    d["lockout"] = (ld == "Admin login disabled").astype(int)
    d["sslvpn_fail"] = (ld == "SSL VPN login fail").astype(int)
    d["pwd_invalid"] = (rs == "passwd_invalid").astype(int)
    g = d.groupby(["boitier", "bucket"]).agg(
        evenements=("logid", "size"),
        echecs_login=("echec_login", "sum"),
        logins_ok=("login_ok", "sum"),
        lockouts=("lockout", "sum"),
        sslvpn_fails=("sslvpn_fail", "sum"),
        pwd_invalid=("pwd_invalid", "sum"),
        ip_sources_uniques=("srcip", lambda s: s[s != ""].nunique()),
    ).reset_index()
    return g


def detect_bursts(df: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    p = cfg.get("rafales", {})
    win = int(p.get("fenetre_minutes", 60))
    facteur = float(p.get("facteur_mediane", 3.0))
    mode = p.get("mode_seuil", "adaptatif")
    fixe = p.get("seuil_fixe_optionnel")
    rows = []
    d = df.dropna(subset=["timestamp"]).copy()
    for boitier, grp in d.groupby("boitier"):
        ts = grp.set_index("timestamp").sort_index()
        # comptage par fenêtre glissante (résolution = pas)
        counts = ts["logid"].resample(f"{win}min").size()
        if counts.empty:
            continue
        med = counts[counts > 0].median() if (counts > 0).any() else 0
        if mode == "fixe" and fixe is not None:
            seuil = float(fixe)
        else:
            seuil = max(1.0, facteur * float(med))
        for t, c in counts.items():
            if c >= seuil and c > 0:
                rows.append({
                    "boitier": boitier, "debut": t, "fin": t + pd.Timedelta(minutes=win),
                    "evenements": int(c), "seuil_applique": round(seuil, 1),
                    "mediane_ref": round(float(med), 1), "mode": mode,
                })
    return pd.DataFrame(rows)


def _entity_set(df: pd.DataFrame, kind: str) -> set:
    if kind == "comptes_ok":  # comptes ayant réussi un login
        m = df.get("logdesc", "").eq("Admin login successful")
        return set(df.loc[m, "user"].dropna().unique())
    if kind == "src_login_ok":
        m = df.get("logdesc", "").isin(["Admin login successful", "SSL VPN tunnel up"])
        return set(df.loc[m, "srcip"].dropna().unique()) - {""}
    if kind == "cfg_objets":
        m = df.get("cfgpath", "").ne("")
        return set((df.loc[m, "cfgpath"].fillna("") + "/" + df.loc[m, "cfgobj"].fillna("")).unique())
    if kind == "dst_sortantes":
        m = (df.get("type", "").eq("traffic")) & (df.get("subtype", "").eq("local"))
        return set(df.loc[m, "dstip"].dropna().unique()) - {""}
    if kind == "noms_cibles":
        m = df.get("logdesc", "").eq("Admin login failed")
        return set(df.loc[m, "user"].dropna().unique()) - {""}
    if kind == "src_attaque":
        m = df.get("logdesc", "").eq("Admin login failed")
        return set(df.loc[m, "srcip"].dropna().unique()) - {""}
    return set()

ENTITES = [
    ("comptes_ok", "Comptes ayant réussi un login", 1),
    ("src_login_ok", "IP sources des logins réussis", 1),
    ("cfg_objets", "Objets de config touchés", 2),
    ("dst_sortantes", "Destinations sortantes du boîtier", 2),
    ("noms_cibles", "Noms ciblés par brute-force", 3),
    ("src_attaque", "IP sources d'attaque", 3),
]


def diff_entities(df_a: pd.DataFrame, df_b: pd.DataFrame, label_a: str, label_b: str) -> pd.DataFrame:
    rows = []
    for kind, libelle, prio in ENTITES:
        sa, sb = _entity_set(df_a, kind), _entity_set(df_b, kind)
        apparus, disparus = sorted(sb - sa), sorted(sa - sb)
        if prio == 3:
            # entités à fort renouvellement (IP d'attaque, noms ciblés) :
            # on résume en compteurs plutôt que de lister des milliers de valeurs
            if apparus:
                rows.append({"entite": libelle, "prio": prio, "etat": "APPARU",
                             "valeur": f"{len(apparus)} nouvelles valeurs (résumé)",
                             "de": label_a, "vers": label_b})
            if disparus:
                rows.append({"entite": libelle, "prio": prio, "etat": "DISPARU",
                             "valeur": f"{len(disparus)} valeurs absentes (résumé)",
                             "de": label_a, "vers": label_b})
            continue
        for val in apparus:
            rows.append({"entite": libelle, "prio": prio, "etat": "APPARU", "valeur": val,
                         "de": label_a, "vers": label_b})
        for val in disparus:
            rows.append({"entite": libelle, "prio": prio, "etat": "DISPARU", "valeur": val,
                         "de": label_a, "vers": label_b})
    out = pd.DataFrame(rows)
    if not out.empty:
        out["alerte"] = (out["prio"] == 1) & (out["etat"] == "APPARU")
        out = out.sort_values(["alerte", "prio", "entite"], ascending=[False, True, True])
    return out
