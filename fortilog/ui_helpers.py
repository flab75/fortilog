"""Fonctions de préparation des données pour l'UI — testables sans Streamlit."""
from __future__ import annotations
import pandas as pd

from .common import SEV_ORDER

SEV_COLORS = {
    "critique": "#C00000",
    "eleve":    "#E26B0A",
    "moyen":    "#BF8F00",
    "faible":   "#7F7F7F",
    "info":     "#2E75B6",
}

EVENTS_DISPLAY_COLS = [
    "timestamp", "boitier", "severite", "regle", "detail",
    "user", "srcip", "dstip", "logdesc", "source_file",
]


def severity_badge(sev: str) -> str:
    """Retourne une chaîne colorée Markdown pour affichage dans une colonne."""
    color = SEV_COLORS.get(sev, "#888888")
    return f'<span style="color:{color};font-weight:bold">{sev.upper()}</span>'


def prepare_events(events: pd.DataFrame) -> pd.DataFrame:
    """Sélectionne et trie les colonnes pour affichage (sévérité décroissante)."""
    if events is None or events.empty:
        return pd.DataFrame()
    cols = [c for c in EVENTS_DISPLAY_COLS if c in events.columns]
    df = events[cols].copy()
    df["_rank"] = df["severite"].map(SEV_ORDER).fillna(0).astype(int)
    df = df.sort_values("_rank", ascending=False).drop(columns="_rank")
    if "timestamp" in df.columns:
        df["timestamp"] = df["timestamp"].astype(str).str[:19]
    return df.reset_index(drop=True)


def prepare_metrics(meta: dict, events: pd.DataFrame,
                    agg: pd.DataFrame, bursts: pd.DataFrame,
                    chains: pd.DataFrame | None = None) -> dict:
    """Calcule les métriques scalaires pour le tableau de bord."""
    sev_counts = {}
    if events is not None and not events.empty and "severite" in events.columns:
        sev_counts = events["severite"].value_counts().to_dict()

    return {
        "n_files":   meta.get("n_files", 0),
        "n_rows":    meta.get("n_rows", 0),
        "n_dedup":   meta.get("dedup", 0),
        "n_events":  len(events) if events is not None else 0,
        "critique":  sev_counts.get("critique", 0),
        "eleve":     sev_counts.get("eleve", 0),
        "moyen":     sev_counts.get("moyen", 0),
        "n_bursts":  len(bursts) if bursts is not None and not bursts.empty else 0,
        "n_chains":  len(chains) if chains is not None and not chains.empty else 0,
        "n_agg_rows": len(agg) if agg is not None and not agg.empty else 0,
    }


def prepare_agg(agg: pd.DataFrame) -> pd.DataFrame:
    if agg is None or agg.empty:
        return pd.DataFrame()
    df = agg.copy()
    if "bucket" in df.columns:
        df["bucket"] = df["bucket"].astype(str).str[:10]
    return df.reset_index(drop=True)


def prepare_bursts(bursts: pd.DataFrame) -> pd.DataFrame:
    if bursts is None or bursts.empty:
        return pd.DataFrame()
    df = bursts.copy()
    for col in ("debut", "fin"):
        if col in df.columns:
            df[col] = df[col].astype(str).str[:16]
    return df.reset_index(drop=True)


def prepare_chains(chains: pd.DataFrame) -> pd.DataFrame:
    """Formate les chaînes suspectes pour affichage (timestamps tronqués)."""
    if chains is None or chains.empty:
        return pd.DataFrame()
    df = chains.copy()
    for col in ("debut", "fin"):
        if col in df.columns:
            df[col] = df[col].astype(str).str[:19]
    return df.reset_index(drop=True)


def prepare_diff(diff: pd.DataFrame) -> pd.DataFrame:
    if diff is None or diff.empty:
        return pd.DataFrame()
    df = diff.copy()
    if "alerte" in df.columns:
        df = df.sort_values("alerte", ascending=False)
    return df.reset_index(drop=True)
