"""Tests pour confaudit.py : parsing CLI FortiGate + grille d'audit de compromission."""
from fortilog import confaudit
from tests.conftest import FIXTURES


def _audit(name, cfg):
    text = (FIXTURES / name).read_text()
    return confaudit.audit_config(text, cfg, source_file=name, boitier="T1")


# --- Parser ---

def test_parse_tree_and_find_blocks():
    text = (FIXTURES / "confaudit_compromis.conf").read_text()
    root = confaudit.parse_config(text)
    admin_blocks = confaudit.find_blocks(root, "system admin")
    assert len(admin_blocks) == 1
    noms = [c.name for c in admin_blocks[0].children if c.kind == "edit"]
    assert noms == ["adminA", "backdoor", "admin99"]
    # les `set` sont bien rattachés à l'edit courant
    adminA = admin_blocks[0].children[0]
    assert adminA.settings.get("accprofile") == '"super_admin"'
    assert any(k.startswith("trusthost") for k in adminA.settings)


def test_parse_header_user():
    text = (FIXTURES / "confaudit_compromis.conf").read_text()
    assert confaudit.parse_header_user(text) == "ghost"


# --- Grille d'audit (référentiel = config.yaml : admins adminA/adminB/adminA_bk) ---

def test_c1_rogue_admin_critique(cfg):
    f = _audit("confaudit_compromis.conf", cfg)
    rogue = [x for x in f if "hors référentiel" in x["regle"] and x["severite"] == "critique"]
    cibles = {x["detail"] for x in rogue}
    assert any("backdoor" in d for d in cibles)
    assert any("admin99" in d for d in cibles)
    assert not any("adminA " in d for d in cibles)  # adminA est dans le référentiel


def test_c2_admin_sans_trusthost(cfg):
    f = _audit("confaudit_compromis.conf", cfg)
    th = [x for x in f if "trusted-host" in x["regle"]]
    assert any("backdoor" in x["detail"] for x in th)
    assert not any("adminA " in x["detail"] for x in th)  # adminA a un trusthost


def test_c3_rogue_name(cfg):
    f = _audit("confaudit_compromis.conf", cfg)
    voyou = [x for x in f if "voyou" in x["regle"]]
    assert any("admin99" in x["detail"] for x in voyou)  # admin99 matche ^admin\d+$


def test_c4_automation_sensible(cfg):
    f = _audit("confaudit_compromis.conf", cfg)
    autom = [x for x in f if "Automation" in x["regle"]]
    assert len(autom) == 1
    assert "cli-script" in autom[0]["detail"]
    assert "evil-persist" in autom[0]["detail"]


def test_c5_telnet_et_wan(cfg):
    f = _audit("confaudit_compromis.conf", cfg)
    assert any("TELNET" in x["regle"] for x in f)              # internal a telnet
    assert any("WAN" in x["regle"] and "wan1" in x["detail"] for x in f)  # wan1 https/ssh exposé


def test_c6_saved_by_unknown(cfg):
    f = _audit("confaudit_compromis.conf", cfg)
    saver = [x for x in f if "sauvegardée" in x["regle"]]
    assert len(saver) == 1
    assert "ghost" in saver[0]["detail"]


def test_clean_config_no_critique(cfg):
    """Config propre (admins connus + trusthost, pas d'automation sensible, pas de
    telnet, sauvée par adminA) -> aucun critique, pas de constat 'hors référentiel'."""
    f = _audit("confaudit_clean.conf", cfg)
    assert not any(x["severite"] == "critique" for x in f)
    assert not any("hors référentiel" in x["regle"] for x in f)
    assert not any("voyou" in x["regle"] for x in f)
    assert not any("TELNET" in x["regle"] for x in f)


def test_audit_files_dataframe_sorted(cfg):
    df = confaudit.audit_files([FIXTURES / "confaudit_compromis.conf"], cfg)
    assert not df.empty
    assert list(df.columns)[:5] == ["boitier", "source_file", "severite", "regle", "detail"]
    # trié par sévérité décroissante : critique en tête
    assert df.iloc[0]["severite"] == "critique"


def test_audit_files_empty():
    df = confaudit.audit_files([], {})
    assert df.empty
