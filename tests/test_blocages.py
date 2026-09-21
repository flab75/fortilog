"""A2 — efficacité des blocages local-in (descriptif) + A3 (C9 confaudit)."""
from __future__ import annotations
import pandas as pd
import pytest

from fortilog import blocages, confaudit


def _full(rows):
    df = pd.DataFrame(rows)
    df["type"] = "traffic"
    df["subtype"] = "local"
    df["boitier"] = df.get("boitier", "FW-T1")
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def test_ip_bloquee_aucun_acces_depuis():
    df = _full([
        {"srcip": "1.2.3.4", "action": "accept", "policytype": "policy",
         "timestamp": "2026-09-21 13:00:00"},
        *[{"srcip": "1.2.3.4", "action": "deny", "policytype": "local-in-policy",
           "timestamp": f"2026-09-21 13:31:{s:02d}"} for s in (47, 50, 55)],
    ])
    out = blocages.build_blocages(df, {})
    assert len(out) == 1
    r = out.iloc[0]
    assert r["n_drops"] == 3 and r["n_atteint_total"] == 1 and r["n_atteint_apres_drop"] == 0
    assert "bloquée depuis 2026-09-21 13:31:47" in r["statut"]


def test_ip_atteint_encore_malgre_la_regle():
    df = _full([
        {"srcip": "5.6.7.8", "action": "deny", "policytype": "local-in-policy",
         "timestamp": "2026-09-21 13:00:00"},
        {"srcip": "5.6.7.8", "action": "client-rst", "policytype": "policy",
         "timestamp": "2026-09-21 14:00:00"},
    ])
    r = blocages.build_blocages(df, {}).iloc[0]
    assert r["n_atteint_apres_drop"] == 1 and "atteint ENCORE" in r["statut"]


def test_ip_sans_drop_absente_et_deny_hors_local_in_ignore():
    df = _full([
        {"srcip": "9.9.9.9", "action": "accept", "policytype": "policy",
         "timestamp": "2026-09-21 13:00:00"},
        {"srcip": "8.8.8.8", "action": "deny", "policytype": "policy",
         "timestamp": "2026-09-21 13:00:00"},
    ])
    assert blocages.build_blocages(df, {}).empty


def test_colonne_policytype_absente_degrade_sans_erreur():
    df = _full([{"srcip": "1.2.3.4", "action": "deny", "policytype": "local-in-policy",
                 "timestamp": "2026-09-21 13:00:00"}]).drop(columns=["policytype"])
    out = blocages.build_blocages(df, {})
    assert out.empty and list(out.columns) == blocages.COLS


CONF_RESTREINT = 'config vpn ssl settings\n    set source-address "GEO-FR"\nend\n'
CONF_ALL = 'config vpn ssl settings\n    set source-address "all"\nend\n'


def _regles(text, ips=None):
    return {f["regle"] for f in confaudit.audit_config(text, {}, ips_vpn_echec=ips)}


def test_c9_restriction_contournee():
    regles = _regles(CONF_RESTREINT, {"81.1.1.1", "82.2.2.2"})
    assert any("contournée" in r for r in regles)


def test_c9_silencieux_sans_logs():
    assert not any("contournée" in r for r in _regles(CONF_RESTREINT, None))


def test_c8_inchange_sur_source_address_all():
    regles = _regles(CONF_ALL, {"81.1.1.1"})
    assert any("ouvert à toutes les IP" in r for r in regles)
    assert not any("contournée" in r for r in regles)
