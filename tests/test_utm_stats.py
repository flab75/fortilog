# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests pour utm_stats.py : agrégats descriptifs (sans règle) pour utm/ips,
utm/webfilter, utm/dns, utm/antivirus."""
import pandas as pd

from fortilog.utm_stats import build_utm_descriptifs, NOTE
from tests.conftest import FIXTURES, load_fixture


def _full_et_files():
    path = FIXTURES / "utm_descriptif_scenario.log"
    return load_fixture("utm_descriptif_scenario.log"), [path]


def test_top_par_type_utm(cfg):
    full, files = _full_et_files()
    out = build_utm_descriptifs(full, files, cfg)
    assert set(out["type_utm"]) == {"ips", "webfilter", "dns", "antivirus"}
    assert (out["note"] == NOTE).all()

    ips = out[out["type_utm"] == "ips"].sort_values("occurrences", ascending=False)
    assert ips.iloc[0]["valeur"] == "HTTP.URI.SQLI / critical"
    assert ips.iloc[0]["occurrences"] == 2

    wf = out[out["type_utm"] == "webfilter"].sort_values("occurrences", ascending=False)
    assert wf.iloc[0]["valeur"] == "malicious.example.com / Malicious Websites / blocked"
    assert wf.iloc[0]["occurrences"] == 2

    dns = out[out["type_utm"] == "dns"].sort_values("occurrences", ascending=False)
    assert dns.iloc[0]["valeur"] == "mirror0.babylon.network / Malicious Websites / redirect"
    assert dns.iloc[0]["occurrences"] == 2

    av = out[out["type_utm"] == "antivirus"]
    assert av.iloc[0]["valeur"] == "Eicar_Test_File"
    assert av.iloc[0]["occurrences"] == 2


def test_top_n_configurable(cfg):
    full, files = _full_et_files()
    cfg = dict(cfg)
    cfg["utm_descriptif"] = {"top_n": 1}
    out = build_utm_descriptifs(full, files, cfg)
    assert len(out[out["type_utm"] == "ips"]) == 1


def test_type_absent_omis(cfg):
    """Aucune ligne utm/antivirus dans les logs -> aucune ligne 'antivirus' en sortie."""
    full, files = _full_et_files()
    full = full[~((full["type"] == "utm") & (full["subtype"] == "antivirus"))].copy()
    out = build_utm_descriptifs(full, files, cfg)
    assert "antivirus" not in set(out["type_utm"])


def test_vide_si_aucun_utm(cfg):
    full = pd.DataFrame({"type": ["event"], "subtype": ["system"],
                         "source_file": ["x.log"], "_row": [0]})
    out = build_utm_descriptifs(full, [FIXTURES / "utm_descriptif_scenario.log"], cfg)
    assert out.empty


def test_full_vide_ou_none(cfg):
    assert build_utm_descriptifs(None, [], cfg).empty
    assert build_utm_descriptifs(pd.DataFrame(), [], cfg).empty
