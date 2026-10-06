# SPDX-License-Identifier: AGPL-3.0-or-later
"""Grappes d'IP candidates à un blocage (blocklist.py)."""
import pandas as pd
import pytest

from fortilog import blocklist

CFG = {
    "plages_internes": ["10.10.0.0/16"],
    "admins_connus": ["adminA"],
    "utilisateurs_vpn_actifs": ["jdupont"],
    "utilisateurs_locaux": {},
    "blocage_candidats": {"seuil_comptes_inexistants": 3},
}


def _rows(ip, users, logdesc="SSL VPN login fail", t0="2026-09-21 10:00:00"):
    base = pd.Timestamp(t0)
    return [{"srcip": ip, "user": u, "logdesc": logdesc,
             "timestamp": base + pd.Timedelta(seconds=10 * i)}
            for i, u in enumerate(users)]


def _full(rows):
    return pd.DataFrame(rows)


def test_grappe_24_regroupe_les_ip_voisines():
    rows = _rows("77.91.71.5", list("abcdef")) + _rows("77.91.71.9", list("ghijkl"))
    df = blocklist.build_candidats(_full(rows), CFG)
    assert list(df["grappe"]) == ["77.91.71.0/24"]
    assert df.iloc[0]["n_ip"] == 2
    assert df.iloc[0]["n_echecs"] == 12


def test_ip_sous_le_seuil_ignoree():
    df = blocklist.build_candidats(_full(_rows("77.91.71.5", ["a", "b"])), CFG)
    assert df.empty


def test_comptes_du_referentiel_ne_comptent_pas():
    # 4 tentatives mais uniquement sur des comptes QUI EXISTENT -> pas un balayage
    rows = _rows("77.91.71.5", ["adminA", "ADMINA", "jdupont", "Jdupont"])
    assert blocklist.build_candidats(_full(rows), CFG).empty


def test_ip_ayant_reussi_une_session_jamais_proposee():
    rows = _rows("77.91.71.5", list("abcdef"))
    rows += [{"srcip": "77.91.71.5", "user": "jdupont", "logdesc": "SSL VPN tunnel up",
              "timestamp": pd.Timestamp("2026-09-21 12:00:00")}]
    assert blocklist.build_candidats(_full(rows), CFG).empty


def test_24_protege_si_un_voisin_a_reussi_une_session():
    """Garde-fou anti-coupure : le /24 n'est pas proposé, l'IP fautive reste en /32."""
    rows = _rows("77.91.71.5", list("abcdef"))
    rows += [{"srcip": "77.91.71.90", "user": "jdupont", "logdesc": "SSL VPN tunnel up",
              "timestamp": pd.Timestamp("2026-09-21 12:00:00")}]
    df = blocklist.build_candidats(_full(rows), CFG)
    assert list(df["grappe"]) == ["77.91.71.5/32"]


def test_ip_interne_exclue():
    assert blocklist.build_candidats(_full(_rows("10.10.1.62", list("abcdef"))), CFG).empty


def test_infrastructure_connue_exclue():
    cfg = dict(CFG, boitiers={"T1": {"wan": "77.91.71.5"}})
    assert blocklist.build_candidats(_full(_rows("77.91.71.5", list("abcdef"))), cfg).empty


def test_desactivable_et_table_vide_sans_logs():
    cfg = dict(CFG, blocage_candidats={"actif": False})
    assert blocklist.build_candidats(_full(_rows("77.91.71.5", list("abcdef"))), cfg).empty
    assert blocklist.build_candidats(pd.DataFrame(), CFG).empty


def test_cli_brouillon_pose_action_deny_explicite():
    rows = _rows("77.91.71.5", list("abcdef"))
    df = blocklist.build_candidats(_full(rows), CFG)
    cli = blocklist.cli_brouillon(df, CFG)
    assert "BROUILLON" in cli
    assert "set subnet 77.91.71.0 255.255.255.0" in cli
    assert "set action deny" in cli            # B1/C10 : sans ça la règle peut rester inerte
    assert "local-in-deny-unicast enable" in cli   # pour pouvoir vérifier l'effet
    assert blocklist.cli_brouillon(pd.DataFrame(), CFG) == ""


def test_cli_brouillon_32_pour_une_ip_isolee():
    rows = _rows("77.91.71.5", list("abcdef"))
    rows += [{"srcip": "77.91.71.90", "user": "jdupont", "logdesc": "SSL VPN tunnel up",
              "timestamp": pd.Timestamp("2026-09-21 12:00:00")}]
    cli = blocklist.cli_brouillon(blocklist.build_candidats(_full(rows), CFG), CFG)
    assert "set subnet 77.91.71.5 255.255.255.255" in cli
