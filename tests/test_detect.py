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
