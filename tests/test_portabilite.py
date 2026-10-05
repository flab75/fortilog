# SPDX-License-Identifier: AGPL-3.0-or-later
"""Portabilité : les chemins relatifs du config sont résolus par rapport au dossier du
config, jamais du dossier courant — l'outil fonctionne là où il est posé."""
from pathlib import Path

from fortilog.common import resolve_paths, load_config, default_config_path, PROJECT_DIR


def test_chemins_relatifs_resolus_contre_le_dossier_du_config(tmp_path):
    cfg = {"geo_db_path": "data/geo/x.csv", "asn_db_path": "/abs/asn.tsv",
           "fortinet_ranges_file": "ftnt.netset",
           "reputation_lists": [{"nom": "FH", "path": "data/fh.netset", "url": "https://x"},
                                "liste.ipset"],
           "plages_internes": ["10.0.0.0/8"]}
    out = resolve_paths(cfg, tmp_path)
    assert out["geo_db_path"] == str(tmp_path / "data/geo/x.csv")
    assert out["asn_db_path"] == "/abs/asn.tsv"                    # absolu inchangé
    assert out["fortinet_ranges_file"] == str(tmp_path / "ftnt.netset")
    assert out["reputation_lists"][0]["path"] == str(tmp_path / "data/fh.netset")
    assert out["reputation_lists"][0]["url"] == "https://x"
    assert out["reputation_lists"][1] == str(tmp_path / "liste.ipset")
    assert out["plages_internes"] == ["10.0.0.0/8"]                # pas un chemin
    assert cfg["geo_db_path"] == "data/geo/x.csv"                  # entrée non modifiée


def test_tilde_developpe(tmp_path):
    assert resolve_paths({"geo_db_path": "~/g.csv"}, tmp_path)["geo_db_path"] == \
        str(Path.home() / "g.csv")


def test_load_config_independant_du_dossier_courant(tmp_path, monkeypatch):
    d = tmp_path / "projet"
    d.mkdir()
    (d / "c.yaml").write_text("geo_db_path: data/geo.csv\n")
    monkeypatch.chdir(tmp_path)                                    # cwd ≠ dossier du config
    assert load_config(d / "c.yaml")["geo_db_path"] == str(d / "data/geo.csv")


def test_config_par_defaut(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert default_config_path() == str(PROJECT_DIR / "config.yaml")
    (tmp_path / "config.yaml").write_text("{}\n")
    assert default_config_path() == "config.yaml"


def test_config_du_projet_pointe_dans_le_projet():
    cfg = load_config(PROJECT_DIR / "config.yaml")
    assert cfg["geo_db_path"].startswith(str(PROJECT_DIR))


def test_ssl_context_utilise_certifi():
    import certifi
    from fortilog.common import ssl_context
    ctx = ssl_context()
    assert ctx.verify_mode.name == "CERT_REQUIRED"
    assert ctx.cert_store_stats()["x509_ca"] > 0       # magasin non vide
    assert certifi.where()
