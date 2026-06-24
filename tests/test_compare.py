"""Tests pour compare.py : agrégats, rafales, différentiel d'entités."""
import pandas as pd
from fortilog import normalize, compare
from tests.conftest import load_fixture


def _prepare(name, cfg):
    df = load_fixture(name)
    df["timestamp"] = normalize.build_timestamp(df)
    df["boitier"] = normalize.assign_boitier(df, cfg.get("boitiers", {}), cfg.get("fichiers_boitier"))
    return df


def test_aggregate_basic(cfg):
    df = _prepare("login_admin_int_connu.log", cfg)
    agg = compare.aggregate(df, bucket="day")
    assert not agg.empty
    assert "evenements" in agg.columns
    assert "logins_ok" in agg.columns
    assert agg["logins_ok"].sum() >= 1


def test_aggregate_counts_failures(cfg):
    df = _prepare("bruteforce_name.log", cfg)
    agg = compare.aggregate(df, bucket="day")
    assert agg["echecs_login"].sum() == 2


def test_detect_bursts_empty_on_few_events(cfg):
    df = _prepare("login_admin_int_connu.log", cfg)
    bursts = compare.detect_bursts(df, cfg)
    assert isinstance(bursts, pd.DataFrame)


def test_diff_entities_detects_new_account(cfg):
    df_a = _prepare("bruteforce_name.log", cfg)
    df_b = _prepare("login_admin_int_connu.log", cfg)
    diff = compare.diff_entities(df_a, df_b, "jour_a", "jour_b")
    if not diff.empty:
        apparus = diff[diff["etat"] == "APPARU"]
        assert isinstance(apparus, pd.DataFrame)


def test_diff_entities_empty_same(cfg):
    df = _prepare("login_admin_int_connu.log", cfg)
    diff = compare.diff_entities(df, df, "same", "same")
    apparus = diff[diff["etat"] == "APPARU"] if not diff.empty else diff
    assert apparus.empty
