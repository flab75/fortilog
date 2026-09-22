"""Tests pour validate.py : validation du config.yaml."""
import copy
from fortilog.validate import validate_config


def test_valid_config_no_errors(cfg):
    errors = validate_config(cfg)
    assert errors == [], f"Erreurs inattendues sur config valide : {errors}"


def test_missing_required_key(cfg):
    bad = copy.deepcopy(cfg)
    del bad["boitiers"]
    errors = validate_config(bad)
    assert any("boitiers" in e for e in errors)


def test_invalid_cidr(cfg):
    bad = copy.deepcopy(cfg)
    bad["plages_internes"] = ["not-a-cidr"]
    errors = validate_config(bad)
    assert any("CIDR" in e for e in errors)


def test_invalid_boitier_ip(cfg):
    bad = copy.deepcopy(cfg)
    bad["boitiers"]["T1"]["wan"] = "not-an-ip"
    errors = validate_config(bad)
    assert any("IP valide" in e for e in errors)


def test_invalid_regex(cfg):
    bad = copy.deepcopy(cfg)
    bad["comptes_suspects_regex"] = ["[invalid("]
    errors = validate_config(bad)
    assert any("regex invalide" in e for e in errors)


def test_invalid_rapport_max_constats(cfg):
    bad = copy.deepcopy(cfg)
    bad["rapport"] = {"max_constats": 0}
    errors = validate_config(bad)
    assert any("rapport.max_constats" in e for e in errors)


def test_invalid_rafale_fenetre(cfg):
    bad = copy.deepcopy(cfg)
    bad["rafales"]["fenetre_minutes"] = -5
    errors = validate_config(bad)
    assert any("fenetre_minutes" in e for e in errors)


def test_invalid_rafale_mode(cfg):
    bad = copy.deepcopy(cfg)
    bad["rafales"]["mode_seuil"] = "inconnu"
    errors = validate_config(bad)
    assert any("mode_seuil" in e for e in errors)


def test_invalid_destination_ip(cfg):
    bad = copy.deepcopy(cfg)
    bad["destinations_legitimes"]["dns_fortiguard"] = ["not-ip"]
    errors = validate_config(bad)
    assert any("valide" in e for e in errors)


def test_admins_not_list(cfg):
    bad = copy.deepcopy(cfg)
    bad["admins_connus"] = "adminA"
    errors = validate_config(bad)
    assert any("admins_connus" in e for e in errors)


def test_none_config():
    errors = validate_config(None)
    assert len(errors) == 1
    assert "dictionnaire" in errors[0]


def test_missing_rafale_key(cfg):
    bad = copy.deepcopy(cfg)
    del bad["rafales"]["facteur_mediane"]
    errors = validate_config(bad)
    assert any("facteur_mediane" in e for e in errors)


def test_app_ctrl_whitelist_not_list(cfg):
    bad = copy.deepcopy(cfg)
    bad["app_ctrl_whitelist"] = "proxy-safebrowsing.googleapis.com"
    errors = validate_config(bad)
    assert any("app_ctrl_whitelist" in e for e in errors)


def test_geo_db_path_wrong_type(cfg):
    bad = copy.deepcopy(cfg)
    bad["geo_db_path"] = 123
    errors = validate_config(bad)
    assert any("geo_db_path" in e for e in errors)


def test_geo_db_path_null_ok(cfg):
    """Chemin null = enrichissement désactivé, pas une erreur."""
    ok = copy.deepcopy(cfg)
    ok["geo_db_path"] = None
    ok["asn_db_path"] = None
    assert validate_config(ok) == []


def test_top_sources_externes_invalid(cfg):
    bad = copy.deepcopy(cfg)
    bad["top_sources_externes"] = -3
    errors = validate_config(bad)
    assert any("top_sources_externes" in e for e in errors)


def test_pool_vpn_chaine_ou_liste_valide(cfg):
    ok = copy.deepcopy(cfg)
    ok["pool_vpn"] = "10.99.0.0/16"
    assert validate_config(ok) == []
    ok["pool_vpn"] = ["10.99.0.0/16", "10.100.0.0/24"]
    assert validate_config(ok) == []


def test_pool_vpn_cidr_invalide(cfg):
    bad = copy.deepcopy(cfg)
    bad["pool_vpn"] = ["10.0.0.0/24", "not-a-cidr"]
    errors = validate_config(bad)
    assert any("pool_vpn" in e for e in errors)


def test_bruteforce_name_invalid_seuil_invalide(cfg):
    bad = copy.deepcopy(cfg)
    bad["bruteforce_name_invalid"] = {"fenetre_minutes": 60, "seuil_echecs": 0}
    errors = validate_config(bad)
    assert any("bruteforce_name_invalid" in e for e in errors)


def test_acteurs_et_timeline_invalides(cfg):
    bad = copy.deepcopy(cfg)
    bad["acteurs"] = {"max_lignes": 0, "poids": {"critique": "abc"}}
    bad["timeline"] = {"severite_min": "enorme", "max_par_groupe": -1}
    errors = validate_config(bad)
    assert any("acteurs.max_lignes" in e for e in errors)
    assert any("acteurs.poids.critique" in e for e in errors)
    assert any("timeline.severite_min" in e for e in errors)
    assert any("timeline.max_par_groupe" in e for e in errors)


# --- Cohérence référentiel ↔ logs (WAN déclaré introuvable) ---

def _full(rows):
    import pandas as pd
    return pd.DataFrame(rows, columns=["type", "subtype", "srcip", "dstip"])


_CFG_COH = {"boitiers": {"T1": {"wan": "203.0.113.1", "mgmt": "10.10.1.1"}},
            "plages_internes": ["10.10.0.0/16"]}


def test_coherence_ok_quand_le_wan_declare_est_dans_les_logs():
    from fortilog.validate import coherence_referentiel
    full = _full([("traffic", "local", "203.0.113.1", "8.8.8.8")] * 3
                 + [("traffic", "local", "10.10.1.1", "8.8.4.4")] * 3)
    assert coherence_referentiel(full, _CFG_COH) == []


def test_coherence_nomme_l_ip_qui_se_comporte_comme_le_boitier():
    from fortilog.validate import coherence_referentiel
    rows = [("traffic", "local", "94.127.15.189", "1.2.3.4")] * 12 \
        + [("traffic", "local", "5.6.7.8", "94.127.15.189")] * 12 \
        + [("traffic", "local", "10.10.1.1", "9.9.9.9")] * 12
    msgs = coherence_referentiel(_full(rows), _CFG_COH)
    assert msgs and "203.0.113.1" in msgs[0] and "10.10.1.1" not in msgs[0]
    assert any("94.127.15.189" in m and "à vérifier" in m for m in msgs)
    # jamais une conclusion : l'IP interne 10.10.1.1 n'est pas proposée comme candidate
    assert not any("10.10.1.1 se comporte" in m for m in msgs)


def test_coherence_absence_franche_quand_aucun_candidat():
    from fortilog.validate import coherence_referentiel
    rows = [("event", "system", "203.0.113.9", "")] * 5
    msgs = coherence_referentiel(_full(rows), _CFG_COH)
    assert any("ne se comporte comme une interface" in m for m in msgs)


def test_coherence_silencieuse_sans_boitier_ou_sans_logs():
    import pandas as pd
    from fortilog.validate import coherence_referentiel
    assert coherence_referentiel(_full([]), _CFG_COH) == []
    assert coherence_referentiel(_full([("traffic", "local", "1.1.1.1", "2.2.2.2")]),
                                 {"boitiers": {}}) == []
