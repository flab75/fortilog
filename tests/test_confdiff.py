"""Tests pour confdiff.py : comparaison de deux .conf + attribution (qui/quand)."""
import pandas as pd
from fortilog import confdiff
from tests.conftest import FIXTURES


def _diff():
    ok = (FIXTURES / "confdiff_ok.conf").read_text()
    cur = (FIXTURES / "confdiff_current.conf").read_text()
    return confdiff.diff_configs(ok, cur)


def test_detects_added_admin():
    d = _diff()
    row = d[(d["section"] == "system admin") & (d["objet"] == "backdoor")]
    assert len(row) == 1
    assert row.iloc[0]["statut"] == "AJOUTÉ"
    assert row.iloc[0]["criticite"] == "critique"


def test_detects_removed_admin():
    d = _diff()
    row = d[(d["section"] == "system admin") & (d["objet"] == "adminB")]
    assert len(row) == 1
    assert row.iloc[0]["statut"] == "SUPPRIMÉ"


def test_detects_modified_admin_trusthost():
    d = _diff()
    row = d[(d["section"] == "system admin") & (d["objet"] == "adminA")]
    assert len(row) == 1
    assert row.iloc[0]["statut"] == "MODIFIÉ"
    assert "trusthost1" in row.iloc[0]["changements"]


def test_detects_new_firewall_rule():
    d = _diff()
    row = d[(d["section"] == "firewall policy") & (d["objet"] == "99")]
    assert len(row) == 1
    assert row.iloc[0]["statut"] == "AJOUTÉ"


def test_detects_global_setting_change():
    d = _diff()
    row = d[(d["section"] == "system global") & (d["objet"] == "(paramètres)")]
    assert len(row) == 1
    assert "admin-https-redirect" in row.iloc[0]["changements"]


def test_password_value_masked():
    ok = 'config system admin\n edit "x"\n set password ENC SECRET_BLOB_OLD\n next\nend\n'
    cur = 'config system admin\n edit "x"\n set password ENC SECRET_BLOB_NEW\n next\nend\n'
    d = confdiff.diff_configs(ok, cur)
    chg = d.iloc[0]["changements"]
    assert "SECRET_BLOB" not in chg
    assert "masquée" in chg


def test_no_change_empty_diff():
    ok = (FIXTURES / "confdiff_ok.conf").read_text()
    d = confdiff.diff_configs(ok, ok)
    assert d.empty


def test_attribution_from_logs():
    d = _diff()
    events = pd.DataFrame({
        "timestamp": [pd.Timestamp("2026-06-23 14:00:00"), pd.Timestamp("2026-06-23 14:05:00")],
        "user": ["ghost", "ghost"],
        "action": ["Add", "Edit"],
        "cfgpath": ["system.admin", "system.admin"],
        "cfgobj": ["backdoor", "adminA"],
    })
    out = confdiff.attribute_changes(d, events)
    bd = out[out["objet"] == "backdoor"].iloc[0]
    assert bd["auteur"] == "ghost"
    assert bd["quand"].startswith("2026-06-23 14:00")
    # un objet sans event correspondant -> attribution honnête "inconnu"
    fw = out[(out["section"] == "firewall policy") & (out["objet"] == "99")].iloc[0]
    assert "inconnu" in fw["auteur"]


def test_attribution_no_logs():
    d = _diff()
    out = confdiff.attribute_changes(d, pd.DataFrame())
    assert (out["auteur"] == "inconnu (pas de logs)").all()


def test_compare_header_saved_by():
    diff, meta = confdiff.compare(FIXTURES / "confdiff_ok.conf", FIXTURES / "confdiff_current.conf")
    assert meta["ok_saved_by"] == "adminA"
    assert meta["current_saved_by"] == "ghost"
    assert meta["n_changes"] == len(diff)
