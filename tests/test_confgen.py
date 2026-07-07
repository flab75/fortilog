"""Tests pour confgen.py : génération d'un référentiel config.yaml depuis des .conf."""
import yaml
import pytest

from fortilog import confgen
from fortilog.validate import validate_config
from tests.conftest import FIXTURES, REAL_LOGS_T1, require_real_logs

SAMPLE = (FIXTURES / "confgen_sample.conf").read_text()


def test_extract_one_basic_fields():
    o = confgen.extract_one(SAMPLE, "fallback")
    assert o["name"] == "FW-SAMPLE"
    assert o["wan"] == "51.91.100.10"
    # admins locaux + sso-admin
    assert set(o["admins"]) == {"adminA", "adminB", "ssoadminX"}
    assert set(o["locaux"]) == {"guest", "vpnuser1", "vpnuser2"}


def test_extract_one_plages_and_mgmt_heuristic():
    o = confgen.extract_one(SAMPLE, "fallback")
    assert "10.50.0.0/24" in o["plages"]      # interface lan
    assert "172.16.5.0/24" in o["plages"]     # interface dmz
    assert "51.91.100.0/24" not in o["plages"]  # wan exclu
    # mgmt heuristique = LAN d'admin (https/ssh) le plus spécifique
    assert o["mgmt"] == "10.50.0.1"
    assert o["mgmt_heuristique"] is True


def test_extract_one_vpn_and_destinations():
    o = confgen.extract_one(SAMPLE, "fallback")
    assert o["vpn_groups"] == ["VPN Staff"]
    assert o["vpn_users"] == ["vpnuser1", "vpnuser2"]   # membres ∩ utilisateurs locaux
    assert o["ipsec_peers"] == ["198.51.100.50"]
    assert o["dns"] == ["96.45.45.45", "96.45.46.46"]


def test_no_secret_leaks_in_output():
    text = confgen.render_config_yaml(confgen.extract_referential({"fw.conf": SAMPLE}))
    assert "psksecret" not in text and "ENC" not in text and "xxxxxxxx" not in text


def test_rendered_config_is_valid():
    text = confgen.render_config_yaml(confgen.extract_referential({"fw.conf": SAMPLE}))
    cfg = yaml.safe_load(text)
    assert validate_config(cfg) == [], "le config.yaml généré doit passer validate_config"
    # référentiel correctement injecté
    assert cfg["boitiers"]["FW-SAMPLE"]["wan"] == "51.91.100.10"
    assert "VPN Staff" in cfg["groupes_vpn_legitimes"]
    assert "10.50.0.0/24" in cfg["plages_internes"]


def test_merge_multiple_confs():
    second = SAMPLE.replace('set hostname "FW-SAMPLE"', 'set hostname "FW-SECOND"') \
                   .replace('"adminA"', '"adminC"')
    ref = confgen.extract_referential({"a.conf": SAMPLE, "b.conf": second})
    assert set(ref["boitiers"]) == {"FW-SAMPLE", "FW-SECOND"}
    assert {"adminA", "adminB", "adminC", "ssoadminX"} <= set(ref["admins_connus"])
    # utilisateurs locaux restent par boîtier
    assert set(ref["utilisateurs_locaux"]) == {"FW-SAMPLE", "FW-SECOND"}


@pytest.mark.slow
def test_real_conf_t1():
    require_real_logs(REAL_LOGS_T1)
    confs = {p.name: p.read_text(errors="replace") for p in REAL_LOGS_T1.glob("*.conf")}
    assert confs, "aucun .conf dans les vrais logs T1"
    ref = confgen.extract_referential(confs)
    assert ref["boitiers"], "aucun boîtier extrait"
    assert ref["admins_connus"], "aucun admin extrait"
    assert ref["plages_internes"], "aucune plage interne extraite"
    import ipaddress
    for cidr in ref["plages_internes"]:
        ipaddress.ip_network(cidr, strict=False)  # lève ValueError si invalide
    text = confgen.render_config_yaml(ref)
    assert validate_config(yaml.safe_load(text)) == []


def test_extract_pool_vpn_depuis_tunnel_ip_pools():
    """vpn ssl settings -> tunnel-ip-pools -> objet firewall address (iprange)."""
    o = confgen.extract_one(SAMPLE, "fallback")
    assert o["pool_vpn"] == ["10.212.134.0/24"]
    text = confgen.render_config_yaml(confgen.extract_referential({"fw.conf": SAMPLE}))
    assert yaml.safe_load(text)["pool_vpn"] == ["10.212.134.0/24"]


def test_render_pool_vpn_defaut_si_absent():
    """Pool introuvable dans le .conf -> défaut projet rendu (commenté à vérifier)."""
    no_pool = SAMPLE.replace('set tunnel-ip-pools "SSLVPN_TUNNEL_ADDR1"', "")
    text = confgen.render_config_yaml(confgen.extract_referential({"fw.conf": no_pool}))
    assert yaml.safe_load(text)["pool_vpn"] == "10.212.134.0/24"
