"""Tests pour ingest.py : détection de type, listage de fichiers."""
from pathlib import Path
from fortilog.ingest import detect_type, list_log_files, KNOWN_TYPES, UTM_NO_RULES
from tests.conftest import FIXTURES


def test_detect_type_event_system():
    t, s, reconnu = detect_type(FIXTURES / "login_admin_ext.log")
    assert t == "event"
    assert s == "system"
    assert reconnu is True


def test_detect_type_event_vpn():
    t, s, reconnu = detect_type(FIXTURES / "vpn_tunnel_connu.log")
    assert t == "event"
    assert s == "vpn"
    assert reconnu is True


def test_detect_type_traffic_local():
    t, s, reconnu = detect_type(FIXTURES / "traffic_outbound.log")
    assert t == "traffic"
    assert s == "local"
    assert reconnu is True


def test_detect_type_unknown():
    t, s, reconnu = detect_type(FIXTURES / "unknown_type.log")
    assert t == "exotic"
    assert s == "foobar"
    assert reconnu is False


def test_list_log_files():
    files = list_log_files(FIXTURES)
    assert len(files) > 0
    assert all(f.suffix == ".log" for f in files)


def test_known_types_coverage():
    """Les types analysés par des règles sont bien présents dans KNOWN_TYPES."""
    analyzed = {
        ("event", "system"), ("event", "user"), ("event", "vpn"),
        ("traffic", "local"), ("traffic", "forward"), ("utm", "app-ctrl"),
        ("app-ctrl", ""), ("event", "security-rating"),
    }
    assert analyzed <= KNOWN_TYPES
    assert UTM_NO_RULES <= KNOWN_TYPES


def test_utm_generic_recognized(cfg):
    """Un fichier utm/ips est reconnu (UTM_NO_RULES) mais sans règles dédiées."""
    t, s, reconnu = detect_type(FIXTURES / "utm_ips_generic.log")
    assert t == "utm"
    assert s == "ips"
    assert reconnu is True
    assert (t, s) in UTM_NO_RULES
