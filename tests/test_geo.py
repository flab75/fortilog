"""Tests pour geo.py : portée (sans base), enrichissement (avec mini-bases),
dégradation honnête (sans base)."""
import ipaddress
import pandas as pd
import pytest
from fortilog import geo
from tests.conftest import FIXTURES


def _nets():
    return [ipaddress.ip_network(c) for c in
            ["10.10.1.0/24", "10.212.134.0/24", "192.168.180.0/22", "10.20.0.0/16"]]


# --- Portée (aucune base requise) ---

def test_scope_interne():
    assert geo.classify_scope("10.10.1.62", _nets()) == geo.INTERNE
    assert geo.classify_scope("192.168.180.120", _nets()) == geo.INTERNE


def test_scope_externe():
    assert geo.classify_scope("85.11.187.120", _nets()) == geo.EXTERNE
    assert geo.classify_scope("144.31.158.144", _nets()) == geo.EXTERNE


def test_scope_reserve_et_invalide():
    # privé hors référentiel -> reserve ; chaîne non-IP -> invalide
    assert geo.classify_scope("172.31.0.1", _nets()) == geo.RESERVE
    assert geo.classify_scope("pas-une-ip", _nets()) == geo.INVALIDE


# --- RangeTable + lookup ---

def test_country_lookup():
    t = geo.RangeTable.from_file(FIXTURES / "geo_country_mini.csv", ",", (2,))
    assert len(t) == 4
    assert t.lookup("85.11.187.120") == ("GB",)
    assert t.lookup("144.31.158.144") == ("US",)
    assert t.lookup("8.8.8.8") is None     # hors plages


def test_asn_lookup_tsv():
    t = geo.RangeTable.from_file(FIXTURES / "geo_asn_mini.tsv", "\t", (2, 4))
    assert t.lookup("144.31.158.144") == ("14061", "DIGITALOCEAN-ASN")


# --- Enrichisseur ---

def _enricher():
    cfg = {"geo_db_path": str(FIXTURES / "geo_country_mini.csv"),
           "asn_db_path": str(FIXTURES / "geo_asn_mini.tsv")}
    return geo.load_enricher(cfg)


def test_enricher_available():
    assert _enricher().available is True


def test_enricher_absent_degrade():
    """Sans base : enricher indisponible, mais la portée reste calculée."""
    e = geo.load_enricher({"geo_db_path": None, "asn_db_path": None})
    assert e.available is False
    assert e.lookup("85.11.187.120") == {"pays": "", "asn": "", "org": ""}


def test_enricher_bad_path_degrade():
    """Chemin invalide : pas d'erreur fatale, base ignorée."""
    e = geo.load_enricher({"geo_db_path": "/n/existe/pas.csv"})
    assert e.available is False


# --- enrich_events ---

def _events():
    return pd.DataFrame({
        "srcip": ["85.11.187.120", "10.10.1.62", "144.31.158.144"],
        "severite": ["eleve", "info", "critique"],
    })


def test_enrich_events_with_db():
    cfg = {"plages_internes": ["10.10.1.0/24"],
           "geo_db_path": str(FIXTURES / "geo_country_mini.csv"),
           "asn_db_path": str(FIXTURES / "geo_asn_mini.tsv")}
    out = geo.enrich_events(_events(), cfg)
    assert list(out["srcip_portee"]) == [geo.EXTERNE, geo.INTERNE, geo.EXTERNE]
    assert out.loc[0, "srcip_pays"] == "GB"
    assert out.loc[2, "srcip_asn"] == "14061"
    # IP interne -> pas d'enrichissement géo
    assert out.loc[1, "srcip_pays"] == ""


def test_enrich_events_no_db_keeps_scope():
    cfg = {"plages_internes": ["10.10.1.0/24"]}
    out = geo.enrich_events(_events(), cfg)
    assert "srcip_portee" in out.columns
    assert list(out["srcip_portee"]) == [geo.EXTERNE, geo.INTERNE, geo.EXTERNE]
    assert "srcip_pays" not in out.columns   # pas de base -> pas de colonnes géo


def test_enrich_events_empty():
    out = geo.enrich_events(pd.DataFrame(), {})
    assert out.empty


# --- top_external_sources ---

def _full():
    return pd.DataFrame({
        "srcip": (["85.11.187.120"] * 5 + ["144.31.158.144"] * 2
                  + ["10.10.1.62"] * 3),
        "logdesc": (["Admin login failed"] * 5 + ["Admin login failed"] * 2
                    + ["Admin login successful"] * 3),
    })


def test_top_external_sources_ranking():
    cfg = {"plages_internes": ["10.10.1.0/24"],
           "geo_db_path": str(FIXTURES / "geo_country_mini.csv")}
    out = geo.top_external_sources(_full(), cfg, n=10)
    # interne exclu, externes classés par volume
    assert list(out["srcip"]) == ["85.11.187.120", "144.31.158.144"]
    assert out.loc[0, "occurrences"] == 5
    assert out.loc[0, "logins_echoues"] == 5
    assert out.loc[0, "srcip_pays"] == "GB"


def test_top_external_sources_no_db():
    cfg = {"plages_internes": ["10.10.1.0/24"]}
    out = geo.top_external_sources(_full(), cfg, n=10)
    assert list(out["srcip"]) == ["85.11.187.120", "144.31.158.144"]
    assert (out["srcip_pays"] == "").all()


def test_top_external_sources_empty():
    out = geo.top_external_sources(pd.DataFrame(), {})
    assert out.empty


# --- Réputation (threat intel) ---

def _repcfg():
    return {"plages_internes": ["10.10.1.0/24"],
            "reputation_lists": [{"nom": "TEST", "path": str(FIXTURES / "reputation_mini.netset")}]}


def test_reputation_cidr_load_and_match():
    repdb = geo.load_reputation(_repcfg())
    assert repdb.available is True
    assert repdb.match("85.11.187.120") == ["TEST"]   # dans 85.11.187.0/24
    assert repdb.match("203.0.113.10") == ["TEST"]     # IP unique
    assert repdb.match("8.8.8.8") == []                # hors liste


def test_reputation_absent_degrade():
    repdb = geo.load_reputation({"reputation_lists": []})
    assert repdb.available is False
    assert repdb.match("85.11.187.120") == []


def test_reputation_bad_path_ignored():
    repdb = geo.load_reputation({"reputation_lists": [{"nom": "X", "path": "/n/existe/pas"}]})
    assert repdb.available is False


def test_enrich_events_adds_reputation_column():
    out = geo.enrich_events(_events(), _repcfg())
    assert "srcip_reputation" in out.columns
    assert out.loc[0, "srcip_reputation"] == "TEST"    # 85.11.187.120
    assert out.loc[1, "srcip_reputation"] == ""        # 10.10.1.62 interne


def test_reputation_sources_aggregates():
    full = pd.DataFrame({
        "srcip": ["85.11.187.120"] * 4 + ["8.8.8.8"] * 2 + ["10.10.1.62"],
        "logdesc": ["Admin login failed"] * 4 + ["Admin login successful"] * 2 + ["x"],
    })
    out = geo.reputation_sources(full, _repcfg())
    assert list(out["srcip"]) == ["85.11.187.120"]     # seul l'IP en liste remonte
    assert out.loc[0, "occurrences"] == 4
    assert out.loc[0, "logins_echoues"] == 4
    assert out.loc[0, "listes"] == "TEST"


def test_reputation_sources_no_list_empty():
    full = pd.DataFrame({"srcip": ["85.11.187.120"], "logdesc": ["x"]})
    out = geo.reputation_sources(full, {"plages_internes": []})
    assert out.empty


def test_reputation_excludes_internal_bogon():
    """Une IP INTERNE présente dans une liste-bogon (FireHOL inclut 10/8) ne doit
    JAMAIS être signalée malveillante (faux positif classique)."""
    cfg = {"plages_internes": ["10.10.1.0/24"],
           "reputation_lists": [{"nom": "B", "path": str(FIXTURES / "reputation_bogon.netset")}]}
    full = pd.DataFrame({
        "srcip": ["10.10.1.62"] * 3 + ["85.11.187.120"] * 2,
        "logdesc": ["Admin login successful"] * 3 + ["Admin login failed"] * 2,
    })
    out = geo.reputation_sources(full, cfg)
    assert list(out["srcip"]) == ["85.11.187.120"]    # interne 10.10.1.62 exclu
    # idem côté enrichissement d'événements
    ev = pd.DataFrame({"srcip": ["10.10.1.62", "85.11.187.120"], "severite": ["info", "eleve"]})
    enr = geo.enrich_events(ev, cfg)
    assert enr.loc[0, "srcip_reputation"] == ""        # interne -> jamais flaggé
    assert enr.loc[1, "srcip_reputation"] == "B"


def test_top_external_sources_excludes_infra():
    """Le WAN du boîtier et un peer IPsec (IP externes légitimes) sont exclus
    du classement des attaquants."""
    full = pd.DataFrame({
        "srcip": ["203.0.113.1"] * 10 + ["85.11.187.120"] * 3,
        "logdesc": ["Admin login successful"] * 10 + ["Admin login failed"] * 3,
    })
    cfg = {"plages_internes": ["10.10.1.0/24"],
           "boitiers": {"T1": {"wan": "203.0.113.1", "mgmt": "10.10.1.1"}},
           "destinations_legitimes": {"ipsec_peers": ["203.0.113.1"]}}
    out = geo.top_external_sources(full, cfg, n=10)
    assert list(out["srcip"]) == ["85.11.187.120"]   # 203.0.113.1 exclu
