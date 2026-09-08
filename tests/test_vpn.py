# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests de l'encart VPN : 1 ligne = 1 tunnel, appariement up/down, bruit exclu."""
import pandas as pd

from fortilog import ingest, normalize, vpn
from tests.conftest import FIXTURES


def _full(name="vpn_sessions.log"):
    df = ingest.load_file(FIXTURES / name,
                          columns=ingest.ANALYSIS_COLS + ingest.VPN_COLS)
    df["timestamp"] = normalize.build_timestamp(df)
    df["srcip"] = normalize.fill_srcip(df)
    df["boitier"] = "T1"
    return df


def test_une_ligne_par_tunnel_et_appariement(cfg):
    sess, stats = vpn.build_sessions(_full(), cfg)
    assert len(sess) == 3 == stats["n_sessions"]          # 111 fermée, 222 ouverte, 333 orpheline
    s = sess.set_index("tunnelid")
    assert s.loc["111", "statut"] == "fermée"
    assert s.loc["111", "motif_fin"] == "User requested termination of service"
    assert s.loc["222", "statut"] == "ouverte en fin de période"
    assert s.loc["333", "statut"] == "montée avant la période analysée"
    assert stats["n_ouvertes"] == 1 and stats["n_orphelines"] == 1
    assert stats["motifs"]["Lost the connection"] == 1


def test_volumes_et_duree_pris_au_max(cfg):
    """`tunnel down` remet parfois les octets à 0 : la session garde le max vu."""
    s = vpn.build_sessions(_full(), cfg)[0].set_index("tunnelid")
    assert s.loc["111", "envoye_mo"] == "2.0" and s.loc["111", "recu_mo"] == "1.0"
    assert s.loc["111", "duree"] == "40 min"               # duration=2400 s


def test_bruit_tls_et_echecs_comptes_a_part(cfg):
    sess, stats = vpn.build_sessions(_full(), cfg)
    assert stats["n_bruit_tls"] == 2 and stats["n_login_fail"] == 1
    assert "N/A" not in set(sess["user"])                  # aucune session sans utilisateur


def test_legitimite_descriptive(cfg):
    sess = vpn.build_sessions(_full(), cfg)[0].set_index("user")
    assert sess.loc["vpnuser1", "legitimite"].iloc[0].startswith("aucun écart")
    assert "compte hors référentiel" in sess.loc["intrus_inconnu", "legitimite"]
    assert "groupe hors référentiel" in sess.loc["intrus_inconnu", "legitimite"]


def test_sans_2fa_signale_si_conf_fourni(cfg):
    conf = {"vpnuser1": {"nom": "vpnuser1", "two_factor": "", "passwd_time": ""}}
    sess = vpn.build_sessions(_full(), cfg, conf)[0]
    ligne = sess[sess["user"].eq("vpnuser1")].iloc[0]
    assert "compte sans double authentification" in ligne["legitimite"]


def test_sans_log_vpn_table_vide(cfg):
    sess, stats = vpn.build_sessions(pd.DataFrame({"logdesc": ["Admin login failed"]}), cfg)
    assert sess.empty and list(sess.columns) == vpn.SESSION_COLS
    assert stats["n_sessions"] == 0


def test_guide_des_logs():
    from fortilog import logguide
    g = logguide.build_guide([{"name": "a.log", "type": "event", "subtype": "vpn", "rows": 5},
                              {"name": "b.log", "type": "event", "subtype": "zzz", "rows": 2}])
    ligne = g[g["type de log"].eq("event/vpn")].iloc[0]
    assert "a.log (5 lignes)" in ligne["présent"] and "INDISPENSABLE" in ligne["utilité"]
    assert g[g["type de log"].eq("event/system")].iloc[0]["présent"] == "non déposé"
    inconnu = g[g["type de log"].eq("event/zzz")].iloc[0]   # type hors catalogue : dit tel quel
    assert "NON RECONNU" in inconnu["ce que l'outil en fait"]
    assert "event/vpn" in logguide.guide_markdown([])
