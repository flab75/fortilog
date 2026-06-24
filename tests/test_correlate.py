"""Tests pour correlate.py : reconstruction de chaînes d'indices (IoC)."""
import pandas as pd
import pytest
from fortilog import correlate
from tests.conftest import detect_on_fixture


def test_chain_complete_on_compromission(cfg):
    """Le scénario de compromission doit remonter UNE chaîne complète, pas 3 isolés."""
    ev = detect_on_fixture("compromission_scenario.log", cfg)
    chains = correlate.correlate_chains(ev, cfg)
    assert len(chains) >= 1
    c = chains.iloc[0]
    assert c["severite"] == "critique"
    assert c["n_etapes"] == 3
    assert correlate.ENTRY in c["etapes"]
    assert correlate.ESCALATION in c["etapes"]
    assert correlate.EXFIL in c["etapes"]


def test_chain_actor_key(cfg):
    """La chaîne du scénario est corrélée par l'acteur (adminA)."""
    ev = detect_on_fixture("compromission_scenario.log", cfg)
    chains = correlate.correlate_chains(ev, cfg)
    actor_chains = chains[chains["cle_type"] == "acteur"]
    assert not actor_chains.empty
    assert "adminA" in actor_chains["cle"].values


def test_no_chain_on_benign(cfg):
    """Pas de chaîne sur logs bénins."""
    ev = detect_on_fixture("benign_mix.log", cfg)
    chains = correlate.correlate_chains(ev, cfg)
    assert chains.empty


def test_no_chain_single_step(cfg):
    """Un seul login (sans escalade ni exfil) ne forme pas de chaîne."""
    ev = detect_on_fixture("login_admin_ext.log", cfg)
    chains = correlate.correlate_chains(ev, cfg)
    assert chains.empty


def test_no_chain_on_benign_admin_activity(cfg):
    """Activité admin légitime (login INTERNE connu → changement mdp → download logs
    dans la fenêtre) ne doit PAS former de chaîne : l'accès initial n'est pas anormal."""
    ev = detect_on_fixture("benign_admin_activity.log", cfg)
    chains = correlate.correlate_chains(ev, cfg)
    assert chains.empty, f"Fausse chaîne sur activité admin légitime : {chains['detail'].tolist()}"


def test_empty_events():
    chains = correlate.correlate_chains(pd.DataFrame(), {})
    assert chains.empty


def test_window_too_short(cfg):
    """Avec une fenêtre de 2 min, le scénario (étalé sur 10 min) ne forme pas de chaîne."""
    cfg_narrow = dict(cfg)
    cfg_narrow["correlation"] = {"fenetre_minutes": 2,
                                 "sequence_requise": ["ACCES", "COMPTE", "EXFILTRATION"]}
    ev = detect_on_fixture("compromission_scenario.log", cfg_narrow)
    chains = correlate.correlate_chains(ev, cfg_narrow)
    assert chains.empty


def test_step_kind_mapping():
    assert correlate._step_kind("Admin login successful", "login", "") == correlate.ENTRY
    assert correlate._step_kind("SSL VPN tunnel up", "tunnel-up", "") == correlate.ENTRY
    assert correlate._step_kind("Object attribute configured", "Add", "system.admin") == correlate.ESCALATION
    assert correlate._step_kind("Admin performed an action from GUI", "download", "") == correlate.EXFIL
    assert correlate._step_kind("Log file downloaded from GUI", "", "") == correlate.EXFIL
    assert correlate._step_kind("DHCP Ack log", "", "") == ""


def test_effective_ip_from_ui():
    row = pd.Series({"srcip": "", "ui": "GUI(203.0.113.50)"})
    assert correlate._effective_ip(row) == "203.0.113.50"


def test_effective_ip_prefers_srcip():
    row = pd.Series({"srcip": "1.2.3.4", "ui": "GUI(9.9.9.9)"})
    assert correlate._effective_ip(row) == "1.2.3.4"


def test_ordered_search_respects_order():
    """Une séquence dans le désordre (exfil avant accès) ne matche pas."""
    base = pd.Timestamp("2026-06-22 10:00:00")
    steps = [
        (base, correlate.EXFIL, 0),
        (base + pd.Timedelta(minutes=5), correlate.ENTRY, 1),
        (base + pd.Timedelta(minutes=10), correlate.ESCALATION, 2),
    ]
    result = correlate._find_ordered(steps, correlate.DEFAULT_SEQUENCE,
                                     pd.Timedelta(minutes=60))
    # Pas de EXFIL après ESCALATION -> pas de match complet
    assert result is None
