"""Normalisation : horodatage unifié, rattachement boîtier (par IP), déduplication."""
from __future__ import annotations
import ipaddress
import pandas as pd

DEDUP_KEYS = ["eventtime", "logid", "srcip", "user", "action"]


def build_timestamp(df: pd.DataFrame) -> pd.Series:
    dt = pd.to_datetime(
        df.get("date", "").astype(str) + " " + df.get("time", "").astype(str),
        format="%Y-%m-%d %H:%M:%S", errors="coerce",
    )
    return dt


def assign_boitier(df: pd.DataFrame, boitiers: dict, fichiers_hint: dict | None = None) -> pd.Series:
    # map IP -> nom de boîtier (wan + mgmt)
    ip_map: dict[str, str] = {}
    for name, ips in boitiers.items():
        for key in ("wan", "mgmt"):
            if ips.get(key):
                ip_map[str(ips[key])] = name
    dst = df.get("dstip", pd.Series([""] * len(df))).astype(str)
    src = df.get("srcip", pd.Series([""] * len(df))).astype(str)
    res = dst.map(lambda x: ip_map.get(x))
    res = res.fillna(src.map(lambda x: ip_map.get(x)))
    # fallback : boîtier majoritaire du fichier
    if res.notna().any():
        for f, grp in df.groupby("source_file"):
            maj = res[grp.index].dropna()
            if len(maj):
                fill = maj.mode().iat[0]
                res.loc[grp.index] = res.loc[grp.index].fillna(fill)
    # fallback final : indice par nom de fichier (déclaré par l'utilisateur)
    if fichiers_hint:
        sf = df.get("source_file", pd.Series([""] * len(df), index=df.index)).astype(str)
        for name, substrings in fichiers_hint.items():
            for sub in substrings:
                mask = res.isna() & sf.str.contains(sub, regex=False, na=False)
                res.loc[mask] = name
    return res.fillna("inconnu")


def deduplicate(df: pd.DataFrame) -> pd.DataFrame:
    keys = [k for k in DEDUP_KEYS if k in df.columns]
    before = len(df)
    df = df.drop_duplicates(subset=keys, keep="first").copy()
    df.attrs["dedup_removed"] = before - len(df)
    return df
