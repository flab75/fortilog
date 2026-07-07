# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests pour bases.py : âge des bases hors-ligne, seuil, dégradation honnête."""
import os
import time

from fortilog.bases import check_bases


def _cfg(tmp_path, age_max=90):
    geo = tmp_path / "geo.csv"
    geo.write_text("start_ip,end_ip,country_code\n")
    return {"geo_db_path": str(geo), "bases": {"age_max_jours": age_max}}, geo


def test_base_recente_non_perimee(tmp_path):
    cfg, _ = _cfg(tmp_path)
    bases = check_bases(cfg)
    assert len(bases) == 1
    assert bases[0]["age_jours"] == 0
    assert bases[0]["perime"] is False


def test_base_vieillie_perimee(tmp_path):
    cfg, geo = _cfg(tmp_path, age_max=90)
    ancien = time.time() - 100 * 86400
    os.utime(geo, (ancien, ancien))
    bases = check_bases(cfg)
    assert bases[0]["age_jours"] == 100
    assert bases[0]["perime"] is True


def test_seuil_configurable(tmp_path):
    cfg, geo = _cfg(tmp_path, age_max=10)
    vieux = time.time() - 20 * 86400
    os.utime(geo, (vieux, vieux))
    bases = check_bases(cfg)
    assert bases[0]["perime"] is True


def test_base_absente_comportement_inchange(tmp_path):
    cfg = {"geo_db_path": str(tmp_path / "absent.csv")}
    bases = check_bases(cfg)
    assert bases[0]["age_jours"] is None
    assert bases[0]["perime"] is False


def test_aucune_base_configuree():
    assert check_bases({}) == []


def test_reputation_lists_et_fortinet_ranges(tmp_path):
    rep = tmp_path / "firehol.netset"
    rep.write_text("10.0.0.0/8\n")
    ranges = tmp_path / "ranges.netset"
    ranges.write_text("1.2.3.0/24\n")
    cfg = {"fortinet_ranges_file": str(ranges),
           "reputation_lists": [{"nom": "FireHOL L1", "path": str(rep)}]}
    bases = check_bases(cfg)
    noms = {b["nom"] for b in bases}
    assert noms == {"Plages Fortinet", "FireHOL L1"}
