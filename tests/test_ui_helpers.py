"""Tests pour ui_helpers.py — fonctions de préparation hors-UI."""
import pandas as pd
import pytest
from fortilog.ui_helpers import (
    prepare_events, prepare_metrics, prepare_agg,
    prepare_bursts, prepare_diff, prepare_chains, severity_badge, SEV_COLORS,
)


def _make_events():
    return pd.DataFrame([
        {"timestamp": pd.Timestamp("2026-06-23 10:00:00"), "boitier": "T1",
         "severite": "critique", "regle": "Login admin réussi depuis source externe",
         "detail": "user=adminA srcip=203.0.113.5", "user": "adminA",
         "srcip": "203.0.113.5", "dstip": "203.0.113.1", "logdesc": "Admin login successful",
         "source_file": "test.log"},
        {"timestamp": pd.Timestamp("2026-06-23 10:05:00"), "boitier": "T1",
         "severite": "moyen", "regle": "Téléchargement de config via GUI",
         "detail": "par adminA", "user": "adminA",
         "srcip": "", "dstip": "", "logdesc": "Admin performed an action from GUI",
         "source_file": "test.log"},
        {"timestamp": pd.Timestamp("2026-06-23 10:01:00"), "boitier": "T1",
         "severite": "eleve", "regle": "Modif config compte",
         "detail": "system.admin/admin-1", "user": "adminA",
         "srcip": "", "dstip": "", "logdesc": "Object attribute configured",
         "source_file": "test.log"},
    ])


def test_prepare_events_sorted_by_severity():
    ev = prepare_events(_make_events())
    assert not ev.empty
    sevs = ev["severite"].tolist()
    # critique > eleve > moyen
    assert sevs[0] == "critique"
    assert sevs[1] == "eleve"
    assert sevs[2] == "moyen"


def test_prepare_events_selects_columns():
    ev = prepare_events(_make_events())
    assert "regle" in ev.columns
    assert "severite" in ev.columns
    assert "_rank" not in ev.columns


def test_prepare_events_timestamp_truncated():
    ev = prepare_events(_make_events())
    ts = ev["timestamp"].iloc[0]
    assert len(ts) <= 19


def test_prepare_events_empty():
    ev = prepare_events(pd.DataFrame())
    assert ev.empty


def test_prepare_events_none():
    ev = prepare_events(None)
    assert ev.empty


def test_prepare_metrics_counts():
    meta = {"n_files": 2, "n_rows": 1000, "dedup": 50}
    events = _make_events()
    agg = pd.DataFrame([{"boitier": "T1", "bucket": "2026-06-23"}])
    bursts = pd.DataFrame([{"boitier": "T1"}])
    m = prepare_metrics(meta, events, agg, bursts)
    assert m["n_files"] == 2
    assert m["n_rows"] == 1000
    assert m["n_dedup"] == 50
    assert m["n_events"] == 3
    assert m["critique"] == 1
    assert m["eleve"] == 1
    assert m["moyen"] == 1
    assert m["n_bursts"] == 1


def test_prepare_metrics_empty_events():
    meta = {"n_files": 1, "n_rows": 100, "dedup": 0}
    m = prepare_metrics(meta, pd.DataFrame(), pd.DataFrame(), pd.DataFrame())
    assert m["n_events"] == 0
    assert m["critique"] == 0


def test_prepare_agg_bucket_truncated():
    agg = pd.DataFrame([
        {"boitier": "T1", "bucket": pd.Timestamp("2026-06-23 00:00:00"),
         "evenements": 100, "echecs_login": 50}
    ])
    result = prepare_agg(agg)
    assert result["bucket"].iloc[0] == "2026-06-23"


def test_prepare_bursts_timestamps_truncated():
    bursts = pd.DataFrame([
        {"boitier": "T1", "debut": pd.Timestamp("2026-06-23 10:00:00"),
         "fin": pd.Timestamp("2026-06-23 11:00:00"), "evenements": 500}
    ])
    result = prepare_bursts(bursts)
    assert len(result["debut"].iloc[0]) <= 16


def test_prepare_diff_alerts_first():
    diff = pd.DataFrame([
        {"entite": "IP sources", "etat": "APPARU", "valeur": "1.2.3.4",
         "prio": 1, "alerte": True},
        {"entite": "Destinations", "etat": "APPARU", "valeur": "5.6.7.8",
         "prio": 2, "alerte": False},
    ])
    result = prepare_diff(diff)
    assert bool(result.iloc[0]["alerte"]) is True


def test_severity_badge_contains_color():
    badge = severity_badge("critique")
    assert SEV_COLORS["critique"] in badge
    assert "CRITIQUE" in badge


def test_severity_badge_unknown():
    badge = severity_badge("inconnu")
    assert "inconnu" in badge.lower() or "INCONNU" in badge


def test_sev_colors_all_severities():
    for sev in ("critique", "eleve", "moyen", "faible", "info"):
        assert sev in SEV_COLORS
        assert SEV_COLORS[sev].startswith("#")


def test_prepare_chains_truncates_timestamps():
    chains = pd.DataFrame([
        {"chaine_id": 1, "cle_type": "acteur", "cle": "adminA", "boitier": "T1",
         "debut": pd.Timestamp("2026-06-22 10:00:01"),
         "fin": pd.Timestamp("2026-06-22 10:10:00"), "duree_min": 10.0,
         "etapes": "ACCES → COMPTE → EXFILTRATION", "n_etapes": 3,
         "severite": "critique", "detail": "..."},
    ])
    result = prepare_chains(chains)
    assert len(result["debut"].iloc[0]) <= 19
    assert result["n_etapes"].iloc[0] == 3


def test_prepare_chains_empty():
    assert prepare_chains(pd.DataFrame()).empty
    assert prepare_chains(None).empty


def test_prepare_metrics_with_chains():
    meta = {"n_files": 1, "n_rows": 100, "dedup": 0}
    chains = pd.DataFrame([{"chaine_id": 1}, {"chaine_id": 2}])
    m = prepare_metrics(meta, pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), chains)
    assert m["n_chains"] == 2
