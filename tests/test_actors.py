# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests pour actors.py : score de priorisation (P1a) et frise chronologique (P1b)."""
import pandas as pd

from fortilog.actors import SCORE_COL, build_actors, build_timeline


def _events():
    """2 IP externes : A multi-règles + réputation, B mono-règle. + 1 IP d'infra (WAN T1)."""
    return pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-06-23 10:00", "2026-06-23 11:00",   # A : 2 critique, 2 règles
            "2026-06-23 12:00",                        # B : 1 eleve
            "2026-06-23 13:00",                        # infra (WAN T1) : à exclure
        ]),
        "boitier": ["T1", "T2", "T1", "T1"],
        "severite": ["critique", "critique", "eleve", "critique"],
        "regle": ["Login admin réussi depuis source externe",
                  "Tunnel SSL-VPN établi hors référentiel",
                  "Brute-force sur COMPTE VALIDE (passwd_invalid)",
                  "Login admin réussi depuis source externe"],
        "user": ["intrus", "intrus", "", ""],
        "srcip": ["198.51.100.9", "198.51.100.9", "192.0.2.7", "203.0.113.1"],
        "srcip_portee": ["externe"] * 4,
        "srcip_pays": ["RU", "RU", "", ""],
        "srcip_asn": ["12345", "12345", "", ""],
        "srcip_org": ["EVIL-NET", "EVIL-NET", "", ""],
        "srcip_reputation": ["FireHOL L1", "FireHOL L1", "", ""],
        "detail": ["", "", "", ""],
    })


def _full():
    """Données complètes : 4 échecs de login associés à l'IP A / au compte intrus."""
    return pd.DataFrame({
        "logdesc": ["Admin login failed"] * 4 + ["Admin login successful"],
        "srcip": ["198.51.100.9"] * 4 + ["10.10.1.5"],
        "user": ["intrus"] * 4 + ["adminA"],
    })


def test_actors_ordre_composantes_et_exclusion_infra(cfg):
    act = build_actors(_events(), _full(), {}, cfg)
    # IP d'infrastructure (WAN T1 = 203.0.113.1 dans config.yaml) exclue de l'axe IP
    ips = act[act["acteur_type"] == "ip"]["acteur"].tolist()
    assert "203.0.113.1" not in ips
    assert set(ips) == {"198.51.100.9", "192.0.2.7"}
    # tri décroissant : A (2×100 + 50 réputation + 20 règle suppl. = 270) en tête
    top = act.iloc[0]
    assert top["acteur"] == "198.51.100.9" and top["acteur_type"] == "ip"
    assert top[SCORE_COL] == 270
    assert top["n_critique"] == 2 and top["nb_regles"] == 2
    assert top["severite_max"] == "critique"
    assert top["reputation"] == "FireHOL L1"
    assert top["pays"] == "RU" and top["org"] == "EVIL-NET"
    assert top["echecs_login"] == 4
    assert top["boitiers"] == "T1, T2"
    assert str(top["premiere_vue"]) == "2026-06-23 10:00:00"
    assert str(top["derniere_vue"]) == "2026-06-23 11:00:00"
    # B mono-règle : 1×30, pas de réputation, pas de bonus règle
    b = act[act["acteur"] == "192.0.2.7"].iloc[0]
    assert b[SCORE_COL] == 30 and b["nb_regles"] == 1
    # axe compte : intrus agrège ses 2 événements
    c = act[(act["acteur_type"] == "compte") & (act["acteur"] == "intrus")].iloc[0]
    assert c["n_critique"] == 2 and c[SCORE_COL] == 270 - 50  # pas de réputation côté compte
    assert c["echecs_login"] == 4


def test_actors_poids_configurables(cfg):
    cfg = dict(cfg)
    cfg["acteurs"] = {"poids": {"critique": 1, "reputation": 0, "regle_supplementaire": 0}}
    act = build_actors(_events(), None, {}, cfg)
    top = act[act["acteur"] == "198.51.100.9"].iloc[0]
    assert top[SCORE_COL] == 2  # 2 critiques × 1, plus rien d'autre


def test_actors_max_lignes(cfg):
    cfg = dict(cfg)
    cfg["acteurs"] = {"max_lignes": 1}
    act = build_actors(_events(), None, {}, cfg)
    assert len(act) == 1 and act.iloc[0]["acteur"] == "198.51.100.9"


def test_actors_vide_si_aucun_evenement(cfg):
    act = build_actors(pd.DataFrame(), None, {}, cfg)
    assert act.empty and "acteur_type" in act.columns


# --- P1b : frise chronologique ---

def _tl_events():
    """7 événements : 5 consécutifs même (règle, acteur) même heure (rafale),
    1 autre acteur, 1 sous le seuil de sévérité."""
    return pd.DataFrame({
        "timestamp": pd.to_datetime([
            "2026-06-23 10:00", "2026-06-23 10:10", "2026-06-23 10:20",
            "2026-06-23 10:30", "2026-06-23 10:40",       # rafale × 5
            "2026-06-23 09:00",                            # avant, autre acteur
            "2026-06-23 08:00",                            # moyen : filtré
        ]),
        "boitier": ["T1"] * 7,
        "severite": ["eleve"] * 5 + ["critique", "moyen"],
        "regle": ["Brute-force sur COMPTE VALIDE (passwd_invalid)"] * 5
                 + ["Login admin réussi depuis source externe", "Modif config compte"],
        "user": ["adminA"] * 5 + ["", "adminB"],
        "srcip": ["198.51.100.9"] * 5 + ["203.0.113.66", "10.10.1.5"],
        "detail": ["user=adminA"] * 5 + ["srcip=203.0.113.66", "x"],
    })


def test_timeline_ordre_filtre_et_rafale(cfg):
    tl = build_timeline(_tl_events(), cfg)
    # le moyen (08:00) est filtré (défaut severite_min = eleve)
    assert (tl["severite"] != "moyen").all()
    # ordre chronologique
    assert tl["timestamp"].is_monotonic_increasing
    # la rafale de 5 (> max_par_groupe 3) est résumée en UNE ligne, compte exact conservé
    assert len(tl) == 2
    rafale = tl[tl["acteur"] == "adminA"].iloc[0]
    assert rafale["detail"] == "× 5 similaires de 10:00 à 10:40"
    assert rafale["timestamp"] == pd.Timestamp("2026-06-23 10:00")


def test_timeline_sous_seuil_de_groupe_non_regroupe(cfg):
    cfg = dict(cfg)
    cfg["timeline"] = {"max_par_groupe": 5}
    tl = build_timeline(_tl_events(), cfg)
    assert len(tl) == 6  # 5 + 1 critique, aucune ligne résumée
    assert not tl["detail"].str.contains("similaires").any()


def test_timeline_severite_min_configurable(cfg):
    cfg = dict(cfg)
    cfg["timeline"] = {"severite_min": "critique"}
    tl = build_timeline(_tl_events(), cfg)
    assert len(tl) == 1 and tl.iloc[0]["severite"] == "critique"
    assert tl.iloc[0]["acteur"] == "203.0.113.66"  # user vide -> srcip


def test_timeline_vide_si_rien_au_dessus_du_seuil(cfg):
    ev = _tl_events()
    ev["severite"] = "info"
    tl = build_timeline(ev, cfg)
    assert tl.empty and "acteur" in tl.columns
