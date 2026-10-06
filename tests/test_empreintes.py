# SPDX-License-Identifier: AGPL-3.0-or-later
"""Empreinte de dictionnaire + cadence par IP (C1/C2) — descriptif, sans sévérité."""
import pandas as pd

from fortilog import empreintes

CFG = {"empreintes": {"min_tentatives": 5, "max_lignes": 10}}


def _full(ip, users, pas_s=480, t0="2026-09-21 08:00:00", jitter=None):
    base = pd.Timestamp(t0)
    return pd.DataFrame([
        {"srcip": ip, "user": u, "logdesc": "SSL VPN login fail", "boitier": "T1",
         "timestamp": base + pd.Timedelta(seconds=pas_s * i + (jitter[i] if jitter else 0))}
        for i, u in enumerate(users)])


def test_empreinte_compte_les_identifiants_et_en_donne_un_echantillon():
    users = [f"user{i}" for i in range(12)]
    df = empreintes.build_empreintes(_full("77.91.71.5", users), CFG)
    r = df.iloc[0]
    assert r["n_tentatives"] == 12 and r["n_comptes"] == 12
    assert r["echantillon_comptes"].startswith("user0, user1")
    assert "(+4)" in r["echantillon_comptes"]      # 8 montrés, 4 annoncés


def test_doublons_d_identifiant_comptes_une_seule_fois():
    df = empreintes.build_empreintes(_full("77.91.71.5", ["a", "a", "b", "b", "c", "c"]), CFG)
    assert df.iloc[0]["n_tentatives"] == 6 and df.iloc[0]["n_comptes"] == 3


def test_cadence_reguliere_detectee_et_prochaine_extrapolee():
    df = empreintes.build_empreintes(_full("77.91.71.5", list("abcdef"), pas_s=480), CFG)
    r = df.iloc[0]
    assert r["cadence_mediane_s"] == 480.0
    assert "automate" in r["regularite"]
    # dernière tentative 08:40:00 + 480 s, et rien après dans la fenêtre -> prévision
    assert "prochaine attendue vers 2026-09-21 08:48:00" in r["suite"]
    assert "prévision" in r["suite"]


def test_cadence_irreguliere_non_qualifiee_d_automate():
    df = empreintes.build_empreintes(
        _full("77.91.71.5", list("abcdef"), pas_s=60, jitter=[0, 0, 900, 0, 3000, 5]), CFG)
    assert df.iloc[0]["regularite"] == "irrégulière"


def test_ip_sous_le_volume_minimal_ignoree():
    assert empreintes.build_empreintes(_full("77.91.71.5", ["a", "b"]), CFG).empty


def test_succes_et_lignes_sans_user_hors_empreinte():
    f = _full("77.91.71.5", list("abcde"))
    f.loc[0, "logdesc"] = "SSL VPN tunnel up"   # pas un échec -> hors empreinte
    assert empreintes.build_empreintes(f, CFG).empty


def test_desactivable_et_dataframe_vide():
    cfg = {"empreintes": {"actif": False}}
    assert empreintes.build_empreintes(_full("77.91.71.5", list("abcdef")), cfg).empty
    assert empreintes.build_empreintes(pd.DataFrame(), CFG).empty


def test_ip_qui_s_est_tue_dit_les_intervalles_manques():
    """L'IP tape toutes les 60 s puis s'arrête ; les logs, eux, continuent."""
    f = _full("77.91.71.5", list("abcdef"), pas_s=60)
    f = pd.concat([f, pd.DataFrame([{"srcip": "77.91.71.9", "user": "z",
                                     "logdesc": "SSL VPN login fail", "boitier": "T1",
                                     "timestamp": pd.Timestamp("2026-09-21 08:15:00")}])],
                  ignore_index=True)
    r = empreintes.build_empreintes(f, CFG)
    r = r[r["srcip"] == "77.91.71.5"].iloc[0]
    assert "aucune tentative depuis 2026-09-21 08:05:00" in r["suite"]
    assert "10 intervalle(s) manqué(s)" in r["suite"]
