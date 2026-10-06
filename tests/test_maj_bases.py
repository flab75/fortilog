# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests pour maj_bases.py : péremption par rythme du producteur, remplacement atomique,
dégradation honnête (réseau absent, fichier non conforme). Aucun accès réseau : le
téléchargement est simulé."""
import datetime as dt
import io
import os
import time
import urllib.error

import pytest

from fortilog import maj_bases, fetch_fortinet_ranges
from fortilog.main import _maj_bases_cli
from fortilog.validate import validate_config

NETSET_OK = "# liste\n" + "\n".join(f"203.0.{i // 256}.{i % 256}/32" for i in range(150)) + "\n"
GEO_OK = "\n".join(f"1.0.{i}.0,1.0.{i}.255,AU" for i in range(20)) + "\n"
HTML = "<html><body>Error 503</body></html>\n"
TODAY = dt.date(2026, 10, 5)


@pytest.fixture
def fake_net(monkeypatch):
    """Simule le réseau : `pages[url] = contenu` ; URL absente -> HTTP 404."""
    pages, appels = {}, []

    def _dl(url, dest, timeout):
        appels.append(url)
        if url not in pages:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO())
        if isinstance(pages[url], Exception):
            raise pages[url]
        dest.write_text(pages[url], encoding="utf-8")

    monkeypatch.setattr(maj_bases, "_telecharger", _dl)
    monkeypatch.setitem(maj_bases.MIN_LIGNES, "geo", 10)
    return pages, appels


def _vieillir(path, jours):
    t = time.time() - jours * 86400
    os.utime(path, (t, t))


def _rep_cfg(path, url="https://ex/fh.netset"):
    return {"reputation_lists": [{"nom": "FireHOL L1", "path": str(path), "url": url}]}


def test_reputation_recente_pas_de_telechargement(tmp_path, fake_net):
    pages, appels = fake_net
    f = tmp_path / "fh.netset"
    f.write_text(NETSET_OK, encoding="utf-8")
    res = maj_bases.mettre_a_jour(_rep_cfg(f))
    assert res[0]["statut"] == maj_bases.A_JOUR
    assert appels == []


def test_reputation_perimee_remplacee(tmp_path, fake_net):
    pages, appels = fake_net
    f = tmp_path / "fh.netset"
    f.write_text("# ancienne\n10.0.0.0/8\n", encoding="utf-8")
    _vieillir(f, 2)
    pages["https://ex/fh.netset"] = NETSET_OK
    res = maj_bases.mettre_a_jour(_rep_cfg(f))
    assert res[0]["statut"] == maj_bases.MAJ
    assert f.read_text(encoding="utf-8") == NETSET_OK
    assert (tmp_path / "fh.netset.maj.json").exists()
    assert not list(tmp_path.glob("*.tmp"))          # aucun temporaire laissé


def test_page_html_n_ecrase_pas_la_base(tmp_path, fake_net):
    pages, _ = fake_net
    f = tmp_path / "fh.netset"
    f.write_text(NETSET_OK, encoding="utf-8")
    _vieillir(f, 2)
    pages["https://ex/fh.netset"] = HTML
    res = maj_bases.mettre_a_jour(_rep_cfg(f))
    assert res[0]["statut"] == maj_bases.ECHEC
    assert "conservée" in res[0]["detail"]
    assert f.read_text(encoding="utf-8") == NETSET_OK
    assert not list(tmp_path.glob("*.tmp"))


def test_reseau_absent_base_conservee(tmp_path, fake_net):
    pages, _ = fake_net
    f = tmp_path / "fh.netset"
    f.write_text(NETSET_OK, encoding="utf-8")
    _vieillir(f, 2)
    pages["https://ex/fh.netset"] = urllib.error.URLError("no route to host")
    res = maj_bases.mettre_a_jour(_rep_cfg(f))
    assert res[0]["statut"] == maj_bases.ECHEC
    assert f.read_text(encoding="utf-8") == NETSET_OK


def test_liste_sans_url_signalee_sans_source(tmp_path, fake_net):
    _, appels = fake_net
    res = maj_bases.mettre_a_jour({"reputation_lists": [{"nom": "X", "path": str(tmp_path / "x")}]})
    assert res[0]["statut"] == maj_bases.SANS_SOURCE
    assert appels == []


def test_force_retelecharge_une_base_a_jour(tmp_path, fake_net):
    pages, appels = fake_net
    f = tmp_path / "fh.netset"
    f.write_text(NETSET_OK, encoding="utf-8")
    pages["https://ex/fh.netset"] = NETSET_OK
    res = maj_bases.mettre_a_jour(_rep_cfg(f), force=True)
    assert res[0]["statut"] == maj_bases.MAJ
    assert appels == ["https://ex/fh.netset"]


def test_seuil_reglable(tmp_path, fake_net):
    _, appels = fake_net
    f = tmp_path / "fh.netset"
    f.write_text(NETSET_OK, encoding="utf-8")
    _vieillir(f, 2)
    cfg = {**_rep_cfg(f), "bases": {"maj": {"reputation_jours": 3}}}
    assert maj_bases.mettre_a_jour(cfg)[0]["statut"] == maj_bases.A_JOUR
    assert appels == []


def test_base_absente_est_telechargee(tmp_path, fake_net):
    pages, _ = fake_net
    f = tmp_path / "sous" / "fh.netset"
    pages["https://ex/fh.netset"] = NETSET_OK
    assert maj_bases.mettre_a_jour(_rep_cfg(f))[0]["statut"] == maj_bases.MAJ
    assert f.exists()


# ── DB-IP mensuel ─────────────────────────────────────────────────────────────

def _geo(tmp_path, mois_mtime):
    f = tmp_path / "dbip.csv"
    f.write_text(GEO_OK, encoding="utf-8")
    t = time.mktime(dt.date(*mois_mtime, 15).timetuple())
    os.utime(f, (t, t))
    return {"geo_db_path": str(f), "bases": {"maj": {"geo_url": "https://ex/dbip-{mois}.csv.gz"}}}, f


def test_geo_nouveau_mois_publie(tmp_path, fake_net):
    pages, appels = fake_net
    cfg, f = _geo(tmp_path, (2026, 6))
    pages["https://ex/dbip-2026-10.csv.gz"] = GEO_OK
    res = maj_bases.mettre_a_jour(cfg, today=TODAY)
    assert res[0]["statut"] == maj_bases.MAJ and "2026-10" in res[0]["detail"]
    assert appels == ["https://ex/dbip-2026-10.csv.gz"]


def test_geo_mois_courant_pas_publie_repli_mois_precedent(tmp_path, fake_net):
    pages, appels = fake_net
    cfg, f = _geo(tmp_path, (2026, 6))
    pages["https://ex/dbip-2026-09.csv.gz"] = GEO_OK
    res = maj_bases.mettre_a_jour(cfg, today=TODAY)
    assert res[0]["statut"] == maj_bases.MAJ and "2026-09" in res[0]["detail"]
    # le mois suivant, le sidecar dit « 2026-09 » : on retente octobre, puis on s'arrête
    appels.clear()
    res = maj_bases.mettre_a_jour(cfg, today=TODAY)
    assert res[0]["statut"] == maj_bases.A_JOUR and "pas encore publié" in res[0]["detail"]
    assert appels == ["https://ex/dbip-2026-10.csv.gz"]


def test_geo_deja_du_mois_aucun_appel(tmp_path, fake_net):
    _, appels = fake_net
    cfg, _ = _geo(tmp_path, (2026, 10))
    assert maj_bases.mettre_a_jour(cfg, today=TODAY)[0]["statut"] == maj_bases.A_JOUR
    assert appels == []


def test_geo_rien_de_publie_echec_base_conservee(tmp_path, fake_net):
    cfg, f = _geo(tmp_path, (2026, 6))
    res = maj_bases.mettre_a_jour(cfg, today=TODAY)
    assert res[0]["statut"] == maj_bases.ECHEC and "HTTP 404" in res[0]["detail"]
    assert f.read_text(encoding="utf-8") == GEO_OK


def test_mois_changement_d_annee():
    assert maj_bases._mois(dt.date(2027, 1, 3), -1) == "2026-12"


# ── Plages Fortinet ───────────────────────────────────────────────────────────

def test_fortinet_perime_regenere(tmp_path, monkeypatch):
    f = tmp_path / "ftnt.netset"
    f.write_text("# vieux\n66.35.16.0/20\n", encoding="utf-8")
    _vieillir(f, 200)
    monkeypatch.setattr(fetch_fortinet_ranges, "fetch_netrefs", lambda org, timeout=30: [
        {"@startAddress": "23.249.48.0", "@endAddress": "23.249.63.255"}])
    res = maj_bases.mettre_a_jour({"fortinet_ranges_file": str(f)})
    assert res[0]["statut"] == maj_bases.MAJ
    assert "23.249.48.0/20" in f.read_text(encoding="utf-8")


def test_fortinet_recent_pas_d_appel(tmp_path, monkeypatch):
    f = tmp_path / "ftnt.netset"
    f.write_text("66.35.16.0/20\n", encoding="utf-8")
    _vieillir(f, 100)
    monkeypatch.setattr(fetch_fortinet_ranges, "fetch_netrefs",
                        lambda *a, **k: pytest.fail("ARIN ne doit pas être interrogé"))
    assert maj_bases.mettre_a_jour({"fortinet_ranges_file": str(f)})[0]["statut"] == maj_bases.A_JOUR


def test_fortinet_reponse_vide_conserve_le_fichier(tmp_path, monkeypatch):
    f = tmp_path / "ftnt.netset"
    f.write_text("66.35.16.0/20\n", encoding="utf-8")
    _vieillir(f, 200)
    monkeypatch.setattr(fetch_fortinet_ranges, "fetch_netrefs", lambda org, timeout=30: [])
    res = maj_bases.mettre_a_jour({"fortinet_ranges_file": str(f)})
    assert res[0]["statut"] == maj_bases.ECHEC
    assert f.read_text(encoding="utf-8") == "66.35.16.0/20\n"


# ── Config, CLI ───────────────────────────────────────────────────────────────

def test_aucune_base_configuree():
    assert maj_bases.mettre_a_jour({}) == []


@pytest.mark.parametrize("patch, attendu", [
    ({"bases": {"maj": {"asn_jours": 0}}}, "bases.maj.asn_jours"),
    ({"bases": {"maj": {"timeout_s": "x"}}}, "bases.maj.timeout_s"),
    ({"bases": {"maj": []}}, "bases.maj"),
    ({"reputation_lists": [{"path": "a", "url": "ftp://x"}]}, "reputation_lists[0].url"),
])
def test_validate_rejette(cfg, patch, attendu):
    errs = validate_config({**cfg, **patch})
    assert any(attendu in e for e in errs), errs


def test_validate_accepte_le_config_du_projet(cfg):
    assert validate_config(cfg) == []


def test_cli_echec_affiche_meme_en_quiet(tmp_path, fake_net, capsys):
    f = tmp_path / "fh.netset"
    cfgf = tmp_path / "c.yaml"
    cfgf.write_text(f"reputation_lists:\n  - {{nom: FH, path: {f}, url: 'https://ex/absent'}}\n", encoding="utf-8")
    _maj_bases_cli(cfgf, quiet=True)
    assert "⚠ FH : échec" in capsys.readouterr().err
