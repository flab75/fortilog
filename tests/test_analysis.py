"""Tests pour analysis.py : rapport de synthèse data-driven."""
import pandas as pd
from fortilog import analysis


def _meta(**kw):
    base = {"n_files": 2, "n_rows": 1000, "dedup": 10, "n_configs": 1}
    base.update(kw)
    return base


def test_report_has_sections():
    text = analysis.build_analysis({}, _meta(), {})
    assert "# RAPPORT D'ANALYSE" in text
    assert "## 1. Périmètre" in text
    assert "## 5. Lecture d'ensemble" in text
    assert "le **verdict reste humain**" in text


def test_report_wan_and_bruteforce_correlation():
    """Config WAN exposée + gros volume d'échecs + IP en réputation -> lecture d'ensemble
    qui relie surface d'attaque et brute-force, sans conclure à une compromission."""
    ca = pd.DataFrame({"boitier": ["T1"], "source_file": ["fw.conf"], "severite": ["eleve"],
                       "regle": ["Accès admin (GUI/SSH) exposé sur interface WAN"], "detail": ["wan1"]})
    agg = pd.DataFrame({"boitier": ["T1"], "bucket": [pd.Timestamp("2026-06-23")],
                        "echecs_login": [50000], "logins_ok": [2]})
    events = pd.DataFrame({"boitier": ["T1"], "severite": ["moyen"], "regle": ["Trafic sortant"]})
    rep = pd.DataFrame({"srcip": ["1.2.3.4"], "listes": ["FireHOL"]})
    tables = {"config_audit": ca, "agg": agg, "events": events, "reputation": rep}
    text = analysis.build_analysis(tables, _meta(), {})
    assert "exposée sur WAN" in text
    assert "Aucune compromission avérée" in text
    assert "connues malveillantes" in text


def test_report_flags_bruteforce_success():
    events = pd.DataFrame({"boitier": ["T1"], "severite": ["critique"],
                           "regle": ["Brute-force potentiellement réussi depuis source externe (SUSPICION)"]})
    agg = pd.DataFrame({"boitier": ["T1"], "bucket": [pd.Timestamp("2026-06-23")],
                        "echecs_login": [9000], "logins_ok": [1]})
    text = analysis.build_analysis({"events": events, "agg": agg}, _meta(), {})
    assert "brute-force possiblement abouti" in text or "potentiellement réussi" in text
    assert "Aucune compromission avérée" not in text  # une brèche possible -> pas ce message


def test_report_config_only_mode():
    """Mode audit-config seul (pas de logs) : le rapport reste cohérent."""
    ca = pd.DataFrame({"boitier": ["T1"], "source_file": ["fw.conf"], "severite": ["critique"],
                       "regle": ["Compte admin hors référentiel (config) — SUSPICION"],
                       "detail": ["admin=backdoor"]})
    text = analysis.build_analysis({"config_audit": ca}, _meta(n_files=0, n_rows=0), {})
    assert "Aucun log analysé" in text
    assert "[À CONFIRMER]" in text  # le compte hors référentiel est marqué à confirmer


def test_report_includes_config_diff():
    """Si une comparaison de config est présente, le rapport global la résume."""
    cd = pd.DataFrame({
        "boitier": ["T1", "T1"], "section": ["system admin", "firewall policy"],
        "objet": ["backdoor", "99"], "statut": ["AJOUTÉ", "AJOUTÉ"],
        "changements": ["+accprofile", "+action=accept"],
        "criticite": ["critique", "eleve"], "auteur": ["ghost", "inconnu"], "quand": ["2026-06-23", ""],
    })
    text = analysis.build_analysis({"config_diff": cd}, _meta(config_ref="ok.conf"), {})
    assert "Changements de configuration vs ok.conf" in text
    assert "compte(s) admin ajouté(s)" in text
    assert "ghost" in text


def test_report_empty_inputs():
    text = analysis.build_analysis({}, _meta(n_files=0, n_rows=0, n_configs=0), {})
    assert "# RAPPORT D'ANALYSE" in text
    assert "Aucun log analysé" in text


def test_report_signals_inconnu_boitier():
    events = pd.DataFrame({"boitier": ["inconnu", "T1"], "severite": ["moyen", "moyen"],
                           "regle": ["x", "y"]})
    text = analysis.build_analysis({"events": events}, _meta(), {})
    assert "inconnu" in text and "config.local.yaml" in text


def _audit_rows(n):
    return pd.DataFrame([
        {"boitier": "T1", "source_file": "fw.conf", "severite": "eleve",
         "regle": "Compte admin sans restriction trusted-host",
         "detail": f"admin=adm{i} (aucun trusthost -> joignable de toute IP)"}
        for i in range(n)
    ])


def test_section2_lists_constats_under_each_rule():
    """Sous chaque règle, ses constats individuels (détail + boîtier) jusqu'à 5, puis résumé."""
    text = analysis.build_analysis({"config_audit": _audit_rows(6)}, _meta(), {})
    assert "Compte admin sans restriction trusted-host — 6 constat(s)." in text
    assert "admin=adm0 (aucun trusthost" in text   # 1er constat de la règle détaillé
    assert "(T1)" in text                            # boîtier indiqué
    assert "et 1 autre" in text                      # le 6e résumé (5 affichés)


def test_section2_detail_per_rule_for_every_rule():
    """Chaque règle a sa propre liste de constats imbriqués."""
    ca = pd.concat([
        pd.DataFrame({"boitier": ["T1"], "source_file": ["fw.conf"], "severite": ["critique"],
                      "regle": ["Compte admin hors référentiel (config) — SUSPICION"],
                      "detail": ["admin=backdoor profil=super_admin"]}),
        _audit_rows(2),
    ], ignore_index=True)
    text = analysis.build_analysis({"config_audit": ca}, _meta(), {})
    assert "Compte admin hors référentiel (config) — SUSPICION — 1 constat(s)." in text
    assert "admin=backdoor profil=super_admin" in text
    assert "Compte admin sans restriction trusted-host — 2 constat(s)." in text
    assert "admin=adm0" in text and "admin=adm1" in text


def test_section2_max_constats_configurable():
    text = analysis.build_analysis({"config_audit": _audit_rows(6)}, _meta(),
                                   {"rapport": {"max_constats": 2}})
    assert "Compte admin sans restriction trusted-host — 6 constat(s)." in text
    assert "admin=adm1" in text and "admin=adm2" not in text  # 2 détaillés seulement
    assert "et 4 autre" in text


def test_section2_suspicion_tagged_a_confirmer():
    """Un constat « — SUSPICION » (ex. SSO cloud inhabituel) est marqué [À CONFIRMER]
    même sans les mots 'hors référentiel'/'voyou'."""
    ca = pd.DataFrame({"boitier": ["T1"], "source_file": ["fw.conf"], "severite": ["eleve"],
                       "regle": ["Compte SSO cloud au nom inhabituel — SUSPICION"], "detail": ["sso=x"]})
    text = analysis.build_analysis({"config_audit": ca}, _meta(), {})
    assert "[À CONFIRMER] Compte SSO cloud au nom inhabituel" in text


def test_section3_lists_top_events():
    events = pd.DataFrame({"timestamp": ["2026-06-23 10:00:00"], "boitier": ["T1"],
                           "severite": ["critique"],
                           "regle": ["Login admin réussi depuis source externe"],
                           "detail": ["user=adminA srcip=203.0.113.5"]})
    text = analysis.build_analysis({"events": events}, _meta(), {})
    assert "Événements les plus sévères" in text
    assert "user=adminA srcip=203.0.113.5" in text


def test_section4_lists_reputation_ips():
    rep = pd.DataFrame({"srcip": ["1.2.3.4", "5.6.7.8"], "listes": ["FireHOL", "FireHOL"],
                        "srcip_pays": ["GB", "US"], "srcip_asn": ["60068", "13335"],
                        "srcip_org": ["DATACAMP", "CLOUDFLARE"],
                        "occurrences": [4907, 10], "logins_echoues": [4907, 0]})
    text = analysis.build_analysis({"reputation": rep}, _meta(), {})
    assert "1.2.3.4 — GB / AS60068 DATACAMP" in text
    assert "FireHOL" in text
