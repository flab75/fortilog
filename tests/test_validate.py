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
    assert any("IP valide" in e for e in errors)


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
