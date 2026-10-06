# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bruit réseau entrant (E1 IPsec phase 1, E2 ICMP externe) — descriptif, sans sévérité."""
import pandas as pd

from fortilog import reseau_stats

CFG = {"plages_internes": ["10.10.0.0/16"], "reseau_descriptif": {"top_n": 2},
       "boitiers": {"T1": {"wan": "94.127.15.189"}}}


def _ipsec(ip, n, reason="peer SA proposal not match local policy", t0="2026-09-21 09:00:00"):
    base = pd.Timestamp(t0)
    return [{"type": "event", "subtype": "vpn", "logdesc": reseau_stats.IPSEC_LOGDESC,
             "srcip": ip, "reason": reason, "app": "", "action": "negotiate",
             "timestamp": base + pd.Timedelta(minutes=i)} for i in range(n)]


def _ping(ip, n, action="accept", t0="2026-09-21 10:00:00"):
    base = pd.Timestamp(t0)
    return [{"type": "traffic", "subtype": "local", "logdesc": "", "srcip": ip,
             "reason": "", "app": "PING", "action": action,
             "timestamp": base + pd.Timedelta(seconds=i)} for i in range(n)]


def test_ipsec_phase1_agrege_par_ip_avec_le_reason_tel_quel():
    df = reseau_stats.build_reseau_descriptifs(pd.DataFrame(_ipsec("64.62.197.218", 5)), CFG)
    r = df.iloc[0]
    assert r["sujet"] == reseau_stats.SUJET_IPSEC and r["source"] == "64.62.197.218"
    assert r["occurrences"] == 5
    assert r["detail"] == "peer SA proposal not match local policy ×5"
    assert str(r["premiere_vue"]) == "2026-09-21 09:00:00"
    assert str(r["derniere_vue"]) == "2026-09-21 09:04:00"
    assert "sans règle d'alerte" in r["note"]


def test_icmp_interne_et_infra_exclus_externe_conserve():
    full = pd.DataFrame(_ping("10.10.16.39", 8) + _ping("94.127.15.189", 4)
                        + _ping("139.177.241.60", 3, action="deny"))
    df = reseau_stats.build_reseau_descriptifs(full, CFG)
    assert list(df["source"]) == ["139.177.241.60"]        # ni le LAN ni le WAN du boîtier
    assert df.iloc[0]["detail"] == "deny ×3"


def test_top_n_borne_chaque_sujet_et_trie_par_volume():
    full = pd.DataFrame(_ipsec("64.62.197.218", 5) + _ipsec("64.62.197.188", 9)
                        + _ipsec("205.210.31.180", 1))
    df = reseau_stats.build_reseau_descriptifs(full, CFG)   # top_n = 2
    assert list(df["source"]) == ["64.62.197.188", "64.62.197.218"]


def test_les_deux_sujets_coexistent_dans_la_meme_table():
    full = pd.DataFrame(_ipsec("64.62.197.218", 2) + _ping("139.177.241.60", 3))
    df = reseau_stats.build_reseau_descriptifs(full, CFG)
    assert set(df["sujet"]) == {reseau_stats.SUJET_IPSEC, reseau_stats.SUJET_ICMP}


def test_sans_champ_app_aucun_icmp_remonte_plutot_qu_une_estimation():
    full = pd.DataFrame([{**l, "app": ""} for l in _ping("139.177.241.60", 5)])
    assert reseau_stats.build_reseau_descriptifs(full, CFG).empty


def test_desactivation_et_logs_vides():
    full = pd.DataFrame(_ipsec("64.62.197.218", 5))
    off = dict(CFG, reseau_descriptif={"actif": False})
    assert reseau_stats.build_reseau_descriptifs(full, off).empty
    assert reseau_stats.build_reseau_descriptifs(pd.DataFrame(), CFG).empty


def test_les_totaux_du_sujet_disent_ce_que_la_troncature_cache():
    full = pd.DataFrame(_ipsec("64.62.197.218", 5) + _ipsec("64.62.197.188", 9)
                        + _ipsec("205.210.31.180", 1))
    df = reseau_stats.build_reseau_descriptifs(full, CFG)   # top_n = 2 sur 3 sources
    assert len(df) == 2
    assert set(df["n_lignes_sujet"]) == {15} and set(df["n_sources_sujet"]) == {3}
