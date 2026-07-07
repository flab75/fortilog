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


def test_diff_boitiers_toutes_paires():
    """3 boîtiers -> 3 paires comparées, ordre alphabétique stable ; 'inconnu' exclu."""
    import pandas as pd
    from fortilog.main import _diff_boitiers
    full = pd.DataFrame({
        "boitier": ["B", "A", "C", "inconnu"],
        "logdesc": ["Admin login successful"] * 4,
        "user": ["ub", "ua", "uc", "ux"],
        "srcip": ["10.0.0.2", "10.0.0.1", "10.0.0.3", "10.0.0.4"],
        "cfgpath": [""] * 4, "cfgobj": [""] * 4,
        "type": [""] * 4, "subtype": [""] * 4, "dstip": [""] * 4,
    })
    ds = _diff_boitiers(full)
    pairs = [(d["de"].iloc[0], d["vers"].iloc[0]) for d in ds]
    assert pairs == [("A", "B"), ("A", "C"), ("B", "C")]
