"""Tests pour normalize.py : timestamp, boîtier, déduplication."""
import pandas as pd
from fortilog import normalize
from tests.conftest import load_fixture, FIXTURES


def test_build_timestamp():
    df = load_fixture("login_admin_ext.log")
    ts = normalize.build_timestamp(df)
    assert ts.notna().all()
    assert ts.iloc[0].year == 2026
    assert ts.iloc[0].month == 6
    assert ts.iloc[0].day == 23


def test_assign_boitier_by_dstip(cfg):
    df = load_fixture("login_admin_ext.log")
    boitier = normalize.assign_boitier(df, cfg["boitiers"], cfg.get("fichiers_boitier"))
    assert boitier.iloc[0] == "T1"


def test_assign_boitier_by_filename_hint(cfg):
    df = load_fixture("vpn_tunnel_connu.log")
    boitier = normalize.assign_boitier(df, cfg["boitiers"], cfg.get("fichiers_boitier"))
    assert boitier.iloc[0] != ""


def test_assign_boitier_unknown(cfg):
    """Un fichier sans IP de boîtier et sans indice de nom → inconnu."""
    df = load_fixture("unknown_type.log")
    boitier = normalize.assign_boitier(df, cfg["boitiers"], cfg.get("fichiers_boitier"))
    assert (boitier == "inconnu").all()


def test_deduplicate_removes_dupes():
    df = load_fixture("dedup_overlap.log")
    before = len(df)
    assert before == 4
    deduped = normalize.deduplicate(df)
    assert len(deduped) == 2
    assert deduped.attrs["dedup_removed"] == 2


def test_deduplicate_preserves_unique():
    df = load_fixture("bruteforce_passwd.log")
    deduped = normalize.deduplicate(df)
    assert len(deduped) == len(df)
