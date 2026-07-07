"""Tests pour detect.py : 1 test positif + 1 test négatif par règle (R1-R9)."""
from tests.conftest import detect_on_fixture, FIXTURES


# --- R1 : Login admin réussi ---

def test_r1_login_externe_critique(cfg):
    ev = detect_on_fixture("login_admin_ext.log", cfg)
    crit = ev[ev["severite"] == "critique"]
    assert len(crit) >= 1
    assert any("externe" in r for r in crit["regle"])


def test_r1_login_interne_connu_info(cfg):
    ev = detect_on_fixture("login_admin_int_connu.log", cfg)
    assert ev[ev["severite"] == "critique"].empty
    assert ev[ev["severite"] == "eleve"].empty
    info = ev[ev["severite"] == "info"]
    assert len(info) >= 1


def test_r1_login_interne_inconnu_eleve(cfg):
    ev = detect_on_fixture("login_admin_int_inconnu.log", cfg)
    eleve = ev[ev["severite"] == "eleve"]
    assert len(eleve) >= 1
    assert any("hors référentiel" in r for r in eleve["regle"])


def test_r1_login_sans_srcip_moyen(cfg):
    """Login admin réussi SANS srcip -> sévérité moyen, libellé dédié, jamais critique."""
    ev = detect_on_fixture("login_admin_no_srcip.log", cfg)
    assert ev[ev["severite"] == "critique"].empty
    ind = ev[ev["regle"].str.contains("indéterminée", na=False)]
    assert len(ind) >= 1
    assert (ind["severite"] == "moyen").all()


# --- R2 : Brute-force sur compte valide ---

def test_r2_passwd_invalid_eleve(cfg):
    ev = detect_on_fixture("bruteforce_passwd.log", cfg)
    eleve = ev[ev["severite"] == "eleve"]
    assert len(eleve) >= 1
    assert any("COMPTE VALIDE" in r for r in eleve["regle"])


def test_r2_name_invalid_pas_de_bruteforce(cfg):
    ev = detect_on_fixture("bruteforce_name.log", cfg)
    bf = ev[ev["regle"].str.contains("COMPTE VALIDE", na=False)]
    assert bf.empty


# --- R3 : Tunnel SSL-VPN hors référentiel ---

def test_r3_vpn_inconnu_critique(cfg):
    ev = detect_on_fixture("vpn_tunnel_inconnu.log", cfg)
    crit = ev[ev["severite"] == "critique"]
    assert len(crit) >= 1
    assert any("VPN" in r for r in crit["regle"])


def test_r3_vpn_connu_pas_critique(cfg):
    ev = detect_on_fixture("vpn_tunnel_connu.log", cfg)
    vpn_crit = ev[(ev["severite"] == "critique") & ev["regle"].str.contains("VPN", na=False)]
    assert vpn_crit.empty


# --- R4 : Modif config compte ---

def test_r4_config_add_eleve(cfg):
    ev = detect_on_fixture("config_account_add.log", cfg)
    eleve = ev[ev["severite"] == "eleve"]
    assert len(eleve) >= 1
    assert any("config" in r.lower() for r in eleve["regle"])


def test_r4_config_edit_moyen(cfg):
    ev = detect_on_fixture("config_account_edit.log", cfg)
    moyen = ev[ev["severite"] == "moyen"]
    assert len(moyen) >= 1


# --- R5 : Nom de compte voyou ---

def test_r5_rogue_on_success_eleve(cfg):
    ev = detect_on_fixture("rogue_account.log", cfg)
    rogue = ev[ev["regle"].str.contains("voyou", na=False)]
    assert len(rogue) >= 1
    assert all(r == "eleve" for r in rogue["severite"])


def test_r5_rogue_on_failure_pas_detecte(cfg):
    """Un nom suspect sur un login échoué NE DOIT PAS déclencher R5."""
    ev = detect_on_fixture("rogue_on_failure.log", cfg)
    rogue = ev[ev["regle"].str.contains("voyou", na=False)]
    assert rogue.empty


# --- R6 : Téléchargement config / logs ---

def test_r6_download_config_moyen(cfg):
    ev = detect_on_fixture("download_config.log", cfg)
    moyen = ev[ev["severite"] == "moyen"]
    assert len(moyen) >= 1
    assert any("config" in r.lower() for r in moyen["regle"])


def test_r6_download_logs_faible(cfg):
    ev = detect_on_fixture("download_logs.log", cfg)
    faible = ev[ev["severite"] == "faible"]
    assert len(faible) >= 1
    assert any("logs" in r.lower() for r in faible["regle"])


# --- R7 : Automation ---

def test_r7_automation_info(cfg):
    ev = detect_on_fixture("automation.log", cfg)
    info = ev[ev["severite"] == "info"]
    assert len(info) >= 1
    assert any("utomation" in r for r in info["regle"])


# --- R8 : Trafic sortant non listé ---

def test_r8_traffic_outbound_non_liste_moyen(cfg):
    ev = detect_on_fixture("traffic_outbound.log", cfg)
    moyen = ev[ev["severite"] == "moyen"]
    assert len(moyen) >= 1
    assert any("sortant" in r for r in moyen["regle"])


def test_r8_traffic_outbound_legit_pas_detecte(cfg):
    ev = detect_on_fixture("traffic_outbound_legit.log", cfg)
    sortant = ev[ev["regle"].str.contains("sortant", na=False)]
    assert sortant.empty


def test_r8_own_wan_ip_not_flagged(cfg):
    """Trafic vers la propre IP WAN du boîtier ne doit pas déclencher R8
    (faux positif : FortiGate qui se parle à lui-même via FortiCloud/FortiGuard)."""
    ev = detect_on_fixture("traffic_outbound_own_wan.log", cfg)
    sortant = ev[ev["regle"].str.contains("sortant", na=False)]
    assert sortant.empty, f"Faux positif R8 sur WAN propre : {sortant['detail'].tolist()}"


def _detect_fortinet_fixture(cfg, enricher=None):
    from fortilog.main import load_file
    from fortilog import normalize, detect
    df = load_file(FIXTURES / "traffic_outbound_fortinet.log")
    df["timestamp"] = normalize.build_timestamp(df)
    df["boitier"] = normalize.assign_boitier(df, cfg.get("boitiers", {}), cfg.get("fichiers_boitier"))
    return detect.run_detection(df, cfg, enricher)


def test_r8_fortinet_flagged_without_exclusion(cfg):
    """Contrôle : sans fichier de plages NI enricher, le trafic vers une IP Fortinet
    (anycast AWS 192.35.158.84) déclenche bien R8 — la fixture est donc pertinente."""
    c = dict(cfg); c["fortinet_ranges_file"] = None
    ev = _detect_fortinet_fixture(c, enricher=None)
    assert not ev[ev["regle"].str.contains("sortant", na=False)].empty


def test_r8_fortinet_excluded_via_file(cfg, tmp_path):
    """(A) Trafic vers une IP Fortinet exclu de R8 via le fichier de plages ARIN."""
    ranges = tmp_path / "fortinet.netset"
    ranges.write_text("# test\n192.35.158.0/24\n", encoding="utf-8")
    c = dict(cfg); c["fortinet_ranges_file"] = str(ranges)
    ev = _detect_fortinet_fixture(c, enricher=None)
    assert ev[ev["regle"].str.contains("sortant", na=False)].empty


def test_r8_fortinet_excluded_via_asn(cfg):
    """(B) Trafic vers une IP Fortinet exclu de R8 via l'org ASN « FORTINET »,
    même sans fichier de plages (cas des anycast AWS sous ASN Amazon)."""
    c = dict(cfg); c["fortinet_ranges_file"] = None

    class _FakeEnricher:
        asn = object()  # présence d'une base ASN
        def lookup(self, ip):
            return {"pays": "", "asn": "16509",
                    "org": "FORTINET" if ip == "192.35.158.84" else "AMAZON-02"}

    ev = _detect_fortinet_fixture(c, enricher=_FakeEnricher())
    assert ev[ev["regle"].str.contains("sortant", na=False)].empty


# --- R9 : VPN -> management ---

def test_r9_vpn_to_mgmt_eleve(cfg):
    ev = detect_on_fixture("vpn_to_mgmt.log", cfg)
    eleve = ev[ev["severite"] == "eleve"]
    assert len(eleve) >= 1
    assert any("VPN" in r and "management" in r for r in eleve["regle"])


def test_r9_pool_vpn_defaut_retrocompatible(cfg):
    """Sans clé pool_vpn dans la config, R9 garde le défaut 10.212.134.0/24."""
    cfg.pop("pool_vpn", None)
    ev = detect_on_fixture("vpn_to_mgmt.log", cfg)
    assert any("management" in r for r in ev["regle"])


def test_r9_pool_vpn_configurable(cfg):
    """Un pool_vpn qui n'inclut pas la source de la fixture -> plus d'alerte R9."""
    cfg["pool_vpn"] = ["10.99.0.0/24"]
    ev = detect_on_fixture("vpn_to_mgmt.log", cfg)
    assert ev[ev["regle"].str.contains("management", na=False)].empty


# --- R10 : UTM/app-ctrl ---

def test_r10a_block_eleve(cfg):
    """Application bloquée par FortiGate → élevé."""
    ev = detect_on_fixture("app_ctrl_block.log", cfg)
    eleve = ev[ev["severite"] == "eleve"]
    assert len(eleve) >= 1
    assert any("bloquée" in r for r in eleve["regle"])


def test_r10a_pass_no_block_alert(cfg):
    """Trafic app-ctrl normal (pass, Network.Service, elevated) → pas d'alerte R10a."""
    ev = detect_on_fixture("app_ctrl_benign.log", cfg)
    block_alerts = ev[ev["regle"].str.contains("bloquée", na=False)]
    assert block_alerts.empty


def test_r10b_critical_non_wl_moyen(cfg):
    """Application à risque critique non bloquée et hors whitelist → moyen."""
    ev = detect_on_fixture("app_ctrl_critical_not_wl.log", cfg)
    moyen = ev[(ev["severite"] == "moyen") & ev["regle"].str.contains("risque critique", na=False)]
    assert len(moyen) >= 1


def test_r10b_critical_wl_pas_detecte(cfg):
    """Application critique dans la whitelist → R10b ne se déclenche pas."""
    ev = detect_on_fixture("app_ctrl_whitelisted.log", cfg)
    r10b = ev[ev["regle"].str.contains("risque critique", na=False)]
    assert r10b.empty


def test_r10c_proxy_non_wl_eleve(cfg):
    """Catégorie Proxy hors whitelist → élevé."""
    ev = detect_on_fixture("app_ctrl_critical_not_wl.log", cfg)
    eleve = ev[(ev["severite"] == "eleve") & ev["regle"].str.contains("proxy", case=False, na=False)]
    assert len(eleve) >= 1


def test_r10c_proxy_wl_pas_detecte(cfg):
    """Proxy dans la whitelist (proxy-safebrowsing.googleapis.com) → R10c ne se déclenche pas."""
    ev = detect_on_fixture("app_ctrl_whitelisted.log", cfg)
    r10c = ev[ev["regle"].str.contains("proxy", case=False, na=False)]
    assert r10c.empty


# --- R11 : Brute-force potentiellement réussi (échecs → succès) ---

def test_r11_bruteforce_success_externe_critique(cfg):
    """6 échecs puis 1 succès depuis la même IP externe → R11 critique."""
    ev = detect_on_fixture("bruteforce_success_ext.log", cfg)
    r11 = ev[ev["regle"].str.contains("Brute-force potentiellement réussi", na=False)]
    assert len(r11) >= 1
    assert all(s == "critique" for s in r11["severite"])
    assert any("6 échecs" in d for d in r11["detail"])


def test_r11_below_threshold_pas_detecte(cfg):
    """2 échecs (< seuil 5) puis succès → R11 ne se déclenche PAS."""
    ev = detect_on_fixture("bruteforce_success_below.log", cfg)
    r11 = ev[ev["regle"].str.contains("potentiellement réussi|après rafale", na=False)]
    assert r11.empty


def test_r11_no_failures_pas_detecte(cfg):
    """Login interne légitime sans échec préalable → aucune alerte R11."""
    ev = detect_on_fixture("benign_admin_activity.log", cfg)
    r11 = ev[ev["regle"].str.contains("potentiellement réussi|après rafale", na=False)]
    assert r11.empty


# --- R12 : Horaires inhabituels ---

def test_r12_offhours_login_detecte(cfg):
    """Login admin réussi à 03h12 → R12 faible (hors plage 7h-20h)."""
    ev = detect_on_fixture("horaires_offhours.log", cfg)
    r12 = ev[ev["regle"].str.contains("hors horaires", na=False)]
    assert len(r12) >= 1
    assert all(s == "faible" for s in r12["severite"])


def test_r12_business_hours_pas_detecte(cfg):
    """Activité admin à 11h (dans la plage ouvrée) → pas d'alerte R12."""
    ev = detect_on_fixture("benign_admin_activity.log", cfg)
    r12 = ev[ev["regle"].str.contains("hors horaires", na=False)]
    assert r12.empty


# --- R13 : rafale d'échecs name_invalid par IP ---

def test_r13_rafale_un_seul_evenement(cfg):
    """25 échecs name_invalid même IP en 25 min -> UN événement (pas 25), détail exact."""
    ev = detect_on_fixture("bruteforce_name_burst.log", cfg)
    r13 = ev[ev["regle"].str.contains("comptes inexistants", na=False)]
    assert len(r13) == 1
    d = r13["detail"].iloc[0]
    assert "25 tentatives name_invalid depuis 198.51.100.77" in d
    assert "entre 23/06 03:00 et 23/06 03:24" in d
    assert "5 comptes distincts" in d
    assert (r13["severite"] == "moyen").all()   # IP externe


def test_r13_sous_seuil_rien(cfg):
    """Moins de seuil_echecs (20) échecs -> aucun événement R13."""
    ev = detect_on_fixture("bruteforce_name.log", cfg)
    assert ev[ev["regle"].str.contains("comptes inexistants", na=False)].empty


def test_r13_passwd_invalid_exclu(cfg):
    """passwd_invalid ne déclenche pas R13 (déjà couvert par R2)."""
    cfg["bruteforce_name_invalid"] = {"fenetre_minutes": 60, "seuil_echecs": 1}
    ev = detect_on_fixture("bruteforce_passwd.log", cfg)
    assert ev[ev["regle"].str.contains("comptes inexistants", na=False)].empty


# --- R14 / R15 : nouveauté comportementale + impossible travel ---

class _FakePaysEnricher:
    """FR : 203.0.113.10/.11/.30 — US : 198.51.100.20 — FR : 203.0.113.31."""
    available = True

    def lookup(self, ip):
        pays = {"203.0.113.10": "FR", "203.0.113.11": "FR", "203.0.113.30": "FR",
                "203.0.113.31": "FR", "198.51.100.20": "US"}.get(ip, "")
        return {"pays": pays, "asn": "", "org": ""}


def _detect_comportement(cfg, enricher=None, comptes_vus_prev=None):
    from fortilog.main import load_file
    from fortilog import normalize, detect
    df = load_file(FIXTURES / "comportement_scenario.log")
    df["timestamp"] = normalize.build_timestamp(df)
    df["boitier"] = normalize.assign_boitier(df, cfg.get("boitiers", {}), cfg.get("fichiers_boitier"))
    return detect.run_detection(df, cfg, enricher, comptes_vus_prev)


def _regle(ev, mot):
    return ev[ev["regle"].str.contains(mot, na=False)]


def test_r14_ip_nouvelle_par_compte(cfg):
    """Chaque nouvelle IP source pour un compte -> info, même sans enricher (aucun besoin de géo)."""
    ev = _detect_comportement(cfg, enricher=None)
    ip_new = _regle(ev, "IP non vue plus tôt")
    # adminA (2 IP distinctes), adminC (2 IP distinctes), adminB (1 IP) -> 5 IP "nouvelles"
    assert len(ip_new) == 5
    assert (ip_new["severite"] == "info").all()


def test_r14_pays_sans_etat_anterieur_libelle_meme_analyse(cfg):
    """Sans comptes_vus_prev : libellé « pas vu plus tôt dans cette analyse »."""
    ev = _detect_comportement(cfg, enricher=_FakePaysEnricher())
    pays_new = _regle(ev, "un pays")
    assert not pays_new.empty
    assert (pays_new["regle"].str.contains("cette analyse")).all()
    assert not (pays_new["regle"].str.contains("historique inclus")).any()
    assert (pays_new["severite"] == "info").all()


def test_r14_pays_avec_etat_anterieur_libelle_historique(cfg):
    """Avec comptes_vus_prev non vide (même pour un autre compte) : libellé « historique inclus »."""
    ev = _detect_comportement(cfg, enricher=_FakePaysEnricher(),
                               comptes_vus_prev={"autre_compte": ["DE"]})
    pays_new = _regle(ev, "un pays")
    assert not pays_new.empty
    assert (pays_new["regle"].str.contains("historique inclus")).all()


def test_r14_pays_deja_connu_pour_ce_compte_pas_signale(cfg):
    """Pays déjà vu pour CE compte dans l'historique persistant -> pas de nouveauté signalée."""
    ev = _detect_comportement(cfg, enricher=_FakePaysEnricher(),
                               comptes_vus_prev={"adminA": ["FR"]})
    pays_new = _regle(ev, "un pays")
    # adminA ne re-signale plus FR (connu) mais signale toujours US (jamais vu) ;
    # adminB et adminC (FR, jamais vus pour eux) restent signalés.
    assert not pays_new[pays_new["detail"].str.contains("user=adminA")]["detail"] \
        .str.contains("pays=FR").any()
    assert pays_new["detail"].str.contains("user=adminA.*pays=US", regex=True).any()


def test_r14_sans_geo_pas_de_nouveaute_pays(cfg):
    """Enricher absent (ou indisponible) : la nouveauté "pays"/impossible travel sont
    silencieusement absentes -- seule la nouveauté IP (sans besoin de géo) reste active."""
    ev = _detect_comportement(cfg, enricher=None)
    assert _regle(ev, "un pays").empty
    assert _regle(ev, "impossible travel").empty
    assert not _regle(ev, "IP non vue plus tôt").empty


def test_r15_impossible_travel_detecte(cfg):
    """adminA : FR à 10:00 puis US à 10:15 (15 min) -> impossible travel, eleve."""
    ev = _detect_comportement(cfg, enricher=_FakePaysEnricher())
    travel = _regle(ev, "impossible travel")
    assert len(travel) == 1
    assert travel["severite"].iloc[0] == "eleve"
    assert "user=adminA" in travel["detail"].iloc[0]
    assert "FR -> US" in travel["detail"].iloc[0]


def test_r15_meme_pays_pas_de_travel(cfg):
    """adminC : FR à 14:00 puis FR à 14:10 (IP différente, même pays) -> pas d'impossible travel."""
    ev = _detect_comportement(cfg, enricher=_FakePaysEnricher())
    travel = _regle(ev, "impossible travel")
    assert not travel["detail"].str.contains("adminC", na=False).any()


def test_r15_fenetre_depassee_pas_de_travel(cfg):
    """adminA revient en FR à 12:30, 2h15 après le passage en US (10:15) : hors fenêtre
    (défaut 60 min) -> le conflit US/FR n'est plus dans la fenêtre glissante, pas de 2e travel."""
    ev = _detect_comportement(cfg, enricher=_FakePaysEnricher())
    travel = _regle(ev, "impossible travel")
    # un seul événement travel au total (celui de 10:15), rien à 12:30
    assert len(travel) == 1
    assert travel["timestamp"].iloc[0].strftime("%H:%M") == "10:15"


def test_r15_sans_enricher_disponible_rien(cfg):
    """enricher présent mais available=False -> dégradation honnête, pas de travel/pays."""
    class _Indisponible:
        available = False
        def lookup(self, ip):
            return {"pays": "", "asn": "", "org": ""}
    ev = _detect_comportement(cfg, enricher=_Indisponible())
    assert _regle(ev, "impossible travel").empty
    assert _regle(ev, "un pays").empty


# --- Mapping MITRE ATT&CK ---

def test_mitre_non_vide_et_format_sur_toutes_les_regles(cfg):
    """Chaque événement des fixtures porte un mitre non vide au format Txxxx — nom."""
    import re
    pat = re.compile(r"^T\d{4}( — .+)?$")
    fixtures = ["login_admin_ext.log", "login_admin_int_connu.log",
                "login_admin_int_inconnu.log", "login_admin_no_srcip.log",
                "bruteforce_passwd.log", "vpn_tunnel_inconnu.log",
                "config_account_add.log", "download_config.log", "download_logs.log",
                "automation.log", "vpn_to_mgmt.log", "app_ctrl_block.log",
                "app_ctrl_critical_not_wl.log", "bruteforce_success_ext.log",
                "horaires_offhours.log", "bruteforce_name_burst.log",
                "compromission_scenario.log"]
    for fx in fixtures:
        ev = detect_on_fixture(fx, cfg)
        assert not ev.empty, f"{fx} : aucune détection"
        assert (ev["mitre"] != "").all(), f"{fx} : mitre vide pour {set(ev.loc[ev['mitre'] == '', 'regle'])}"
        assert all(pat.match(m) for m in ev["mitre"]), f"{fx} : format mitre invalide"


def test_mitre_regle_inconnue_champ_vide():
    """Règle absente du mapping -> champ vide, pas d'erreur."""
    import pandas as pd
    from fortilog.common import MITRE_MAP
    s = pd.Series(["Règle inventée"]).map(MITRE_MAP).fillna("")
    assert s.iloc[0] == ""
