"""Tests pour parse.py : parsing clé=valeur, valeurs quotées avec espaces."""
from fortilog.parse import parse_line


def test_simple_key_value():
    line = 'date=2026-06-23 time=15:30:59 logid="0100032002" type="event"'
    d = parse_line(line)
    assert d["date"] == "2026-06-23"
    assert d["time"] == "15:30:59"
    assert d["logid"] == "0100032002"
    assert d["type"] == "event"


def test_quoted_value_with_spaces():
    line = 'user="adminA" msg="Administrator adminA logged in successfully from https(10.10.1.62)"'
    d = parse_line(line)
    assert d["user"] == "adminA"
    assert "logged in successfully" in d["msg"]


def test_unquoted_value():
    line = "srcip=10.10.1.62 dstip=203.0.113.1 action=login"
    d = parse_line(line)
    assert d["srcip"] == "10.10.1.62"
    assert d["dstip"] == "203.0.113.1"
    assert d["action"] == "login"


def test_mixed_quoted_unquoted():
    line = 'srcip=203.0.113.5 logdesc="Admin login successful" status="success" reason="none"'
    d = parse_line(line)
    assert d["srcip"] == "203.0.113.5"
    assert d["logdesc"] == "Admin login successful"
    assert d["status"] == "success"


def test_empty_quoted_value():
    line = 'user="" srcip=1.2.3.4'
    d = parse_line(line)
    assert d["user"] == ""
    assert d["srcip"] == "1.2.3.4"


def test_empty_line():
    assert parse_line("") == {}


def test_group_with_space():
    line = 'user="vpnuser1" group="VPN GroupA" action="tunnel-up"'
    d = parse_line(line)
    assert d["group"] == "VPN GroupA"


def test_real_login_failed_line():
    line = (
        'date=2026-06-23 time=15:30:59 eventtime=1782221459624823410 tz="+0200" '
        'logid="0100032002" type="event" subtype="system" level="alert" vd="root" '
        'logdesc="Admin login failed" sn="0" user="naji" ui="https(209.50.163.128)" '
        'method="https" srcip=209.50.163.128 dstip=203.0.113.1 action="login" '
        'status="failed" reason="name_invalid" '
        'msg="Administrator naji login failed from https(209.50.163.128) because of invalid user name"'
    )
    d = parse_line(line)
    assert d["logdesc"] == "Admin login failed"
    assert d["user"] == "naji"
    assert d["srcip"] == "209.50.163.128"
    assert d["reason"] == "name_invalid"
    assert "invalid user name" in d["msg"]


# --- P4.1 : échappements Fortinet ---

def test_escaped_backslash_value():
    """Cas RÉEL (brute-force SSH T2) : user="\\\\" -> un backslash, champ suivant intact."""
    line = r'user="\\" ui="ssh(144.31.158.144)" method="ssh" srcip=144.31.158.144'
    d = parse_line(line)
    assert d["user"] == "\\"            # \\ déséchappé en un seul backslash
    assert d["ui"] == "ssh(144.31.158.144)"
    assert d["srcip"] == "144.31.158.144"


def test_escaped_quote_inside_value_keeps_following_fields():
    """Un guillemet LITTÉRAL dans msg (ligne app-ctrl) ne doit PAS décaler apprisk/scertcname
    qui suivent — c'est l'entrée des règles R10b/R10c."""
    line = (
        r'type="utm" subtype="app-ctrl" action="pass" appcat="Proxy" '
        r'msg="Blocked app \"EvilProxy\" detected" apprisk="critical" scertcname="x.example"'
    )
    d = parse_line(line)
    assert d["msg"] == 'Blocked app "EvilProxy" detected'
    assert d["apprisk"] == "critical"          # champ APRÈS msg : alignement préservé
    assert d["scertcname"] == "x.example"


def test_escaped_quote_at_end_of_value():
    line = r'cfgattr="old-password[*]password[*]" msg="value ends with quote \"" action="Edit"'
    d = parse_line(line)
    assert d["msg"] == 'value ends with quote "'
    assert d["action"] == "Edit"


def test_mixed_escapes_in_one_value():
    line = r'msg="path C:\\dir said \"hi\"" status="success"'
    d = parse_line(line)
    assert d["msg"] == 'path C:\\dir said "hi"'
    assert d["status"] == "success"
