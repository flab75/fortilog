# SPDX-License-Identifier: AGPL-3.0-or-later
"""Grille d'audit VECTORISÉE : marque les événements à risque + sévérité.
L'outil SIGNALE ; le verdict reste humain. Aucune conclusion hors logs."""
from __future__ import annotations
import ipaddress
import re
from pathlib import Path
import numpy as np
import pandas as pd

from .common import SEV_ORDER, CFG_ACCOUNT_PATHS, MITRE_MAP, str_col


def _load_cidr_networks(path) -> list:
    """Charge une liste de CIDRs (un par ligne, '#' = commentaire) en réseaux ipaddress.
    Fichier absent/illisible -> liste vide (dégradation honnête, jamais d'erreur fatale)."""
    nets = []
    if not path:
        return nets
    p = Path(path)
    if not p.is_file():
        return nets
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                pass
    except OSError:
        pass
    return nets


def _internal_map(ips, nets) -> dict:
    """Évalue l'appartenance interne une seule fois par IP unique."""
    out = {}
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
            out[ip] = any(a in n for n in nets)
        except ValueError:
            out[ip] = False
    return out


def _bruteforce_success_mask(df, ld, srcip, user, window_min, seuil):
    """R11 : repère les logins admin RÉUSSIS précédés d'au moins `seuil` échecs de
    login sur la MÊME IP source OU le MÊME compte, dans `window_min` minutes.
    Renvoie (hit: bool Series, n_echecs: int Series, par: str Series 'ip'/'compte').
    Corrélation temporelle, donc SUSPICION — jamais une preuve de brèche."""
    hit = pd.Series(False, index=df.index)
    n_ech = pd.Series(0, index=df.index)
    par = pd.Series("", index=df.index)
    if "timestamp" not in df.columns:
        return hit, n_ech, par
    ts = df["timestamp"]
    succ = ld.eq("Admin login successful")
    fail = ld.eq("Admin login failed")
    if not succ.any() or not fail.any():
        return hit, n_ech, par

    win = pd.Timedelta(minutes=window_min)
    fdf = pd.DataFrame({"t": ts[fail], "ip": srcip[fail], "u": user[fail]}).dropna(subset=["t"])
    fails_ip = {k: np.sort(v["t"].values) for k, v in fdf.groupby("ip") if k != ""}
    fails_u = {k: np.sort(v["t"].values) for k, v in fdf.groupby("u") if k != ""}

    for i in df.index[succ]:
        t = ts[i]
        if pd.isna(t):
            continue
        lo, hi = (t - win).to_datetime64(), t.to_datetime64()
        ip, u = srcip[i], user[i]
        c_ip = c_u = 0
        if ip in fails_ip:
            a = fails_ip[ip]
            c_ip = int(np.searchsorted(a, hi, "right") - np.searchsorted(a, lo, "left"))
        if u in fails_u:
            a = fails_u[u]
            c_u = int(np.searchsorted(a, hi, "right") - np.searchsorted(a, lo, "left"))
        c = max(c_ip, c_u)
        if c >= seuil:
            hit[i] = True
            n_ech[i] = c
            par[i] = "ip" if c_ip >= c_u else "compte"
    return hit, n_ech, par


def run_detection(df: pd.DataFrame, cfg: dict, enricher=None, comptes_vus_prev=None) -> pd.DataFrame:
    """`comptes_vus_prev` : snapshot en lecture seule {compte: [pays déjà vus]} issu de
    l'état persistant P2 (suivi.py) ; None/vide -> dégradation « pas vu plus tôt dans
    CETTE analyse » (R14, voir plus bas)."""
    nets = [ipaddress.ip_network(c.split("#")[0].strip()) for c in cfg.get("plages_internes", [])]
    _pool = cfg.get("pool_vpn", "10.212.134.0/24")  # un CIDR ou une liste (R9)
    vpn_net = [ipaddress.ip_network(str(c).split("#")[0].strip())
               for c in ([_pool] if isinstance(_pool, str) else _pool)]
    admins = set(cfg.get("admins_connus", []))
    vpn_users = set(cfg.get("utilisateurs_vpn_actifs", []))
    vpn_groups = set(cfg.get("groupes_vpn_legitimes", []))
    locaux = set(sum(cfg.get("utilisateurs_locaux", {}).values(), []))
    known_users = admins | vpn_users | locaux
    _pats = [p.replace("(?i)", "") for p in cfg.get("comptes_suspects_regex", [])]
    rogue_re = re.compile("|".join(f"(?:{p})" for p in _pats), re.IGNORECASE) if _pats else None
    _raw_dst = list(map(str, sum(cfg.get("destinations_legitimes", {}).values(), [])))
    legit_dst = {e for e in _raw_dst if "/" not in e}   # IP simples → isin()
    _legit_nets = []
    for e in _raw_dst:
        if "/" in e:
            try: _legit_nets.append(ipaddress.ip_network(e, strict=False))
            except ValueError: pass
    mgmt_ips = {str(b.get("mgmt")) for b in cfg.get("boitiers", {}).values()}
    wan_ips = {str(b.get("wan")) for b in cfg.get("boitiers", {}).values() if b.get("wan")}

    g = lambda c: str_col(df, c)
    ld, st, rs = g("logdesc"), g("status"), g("reason")
    user, srcip, dstip = g("user"), g("srcip"), g("dstip")
    cfgpath, cfgobj, action, grp = g("cfgpath"), g("cfgobj"), g("action"), g("group")
    typ, sub = g("type"), g("subtype")

    uniq_ips = set(srcip.unique()) | set(dstip.unique())
    intern = _internal_map(uniq_ips, nets)
    src_int = srcip.map(intern).fillna(False)
    src_vpn = srcip.map(_internal_map(set(srcip.unique()), vpn_net)).fillna(False)
    dst_legit_net = _internal_map(set(dstip.unique()), _legit_nets) if _legit_nets else {}

    # Destinations Fortinet (FortiGuard/FortiCloud/FortiSASE) — trafic boîtier légitime,
    # exclues de R8 par DEUX mécanismes complémentaires :
    #   (A) plages ARIN statiques (fortinet_ranges_file, énumération par propriété : capte
    #       aussi les anycast hébergés chez AWS, invisibles d'un filtre ASN) ;
    #   (B) org ASN « FORTINET » au runtime (base iptoasn déjà chargée dans `enricher`).
    uniq_dst = set(dstip.unique())
    fortinet_dst = set()
    _fnets = _load_cidr_networks(cfg.get("fortinet_ranges_file"))
    if _fnets:
        fmap = _internal_map(uniq_dst, _fnets)
        fortinet_dst |= {ip for ip, hit in fmap.items() if hit}
    if enricher is not None and getattr(enricher, "asn", None) is not None:
        for ip in uniq_dst:
            if ip in fortinet_dst:
                continue
            if "FORTINET" in (enricher.lookup(ip).get("org") or "").upper():
                fortinet_dst.add(ip)

    parts = []

    def flag(mask, regle, severite, detail):
        if mask.any():
            sub_df = df.loc[mask, :].copy()
            sub_df["regle"] = regle
            sub_df["severite"] = severite
            sub_df["detail"] = detail[mask]
            parts.append(sub_df)

    # 1. Login admin réussi. srcip absent -> portée inconnue : ni interne ni externe
    # (jamais inventer une portée), libellé dédié en sévérité moyenne.
    ok = ld.eq("Admin login successful")
    no_src = srcip.eq("")
    flag(ok & no_src, "Login admin réussi, source indéterminée (srcip absent)", "moyen",
         ("user=" + user))
    ext = ok & ~src_int & ~no_src
    flag(ext, "Login admin réussi depuis source externe", "critique",
         ("user=" + user + " srcip=" + srcip))
    unk = ok & src_int & ~user.isin(admins)
    flag(unk, "Login admin réussi par compte hors référentiel", "eleve", ("user=" + user))
    known_ok = ok & src_int & user.isin(admins)
    flag(known_ok, "Login admin réussi (interne, connu)", "info", ("user=" + user + " srcip=" + srcip))

    # 2. Brute-force sur compte valide
    flag(ld.eq("Admin login failed") & rs.eq("passwd_invalid"),
         "Brute-force sur COMPTE VALIDE (passwd_invalid)", "eleve",
         ("user=" + user + " srcip=" + srcip))

    # 3. Tunnel SSL-VPN hors référentiel
    tun = ld.eq("SSL VPN tunnel up")
    bad_tun = tun & ((~user.isin(known_users) & user.ne("")) | (~grp.isin(vpn_groups) & grp.ne("")))
    flag(bad_tun, "Tunnel SSL-VPN établi hors référentiel", "critique",
         ("user=" + user + " group=" + grp + " remip=" + srcip))

    # 4. Modif config compte/SSO
    iscfg = cfgpath.isin(CFG_ACCOUNT_PATHS)
    sev = pd.Series("moyen", index=df.index)
    sev = sev.mask(action.eq("Add"), "eleve")
    sev = sev.mask(~user.isin(admins) & user.ne(""), "critique")
    for level in ("critique", "eleve", "moyen"):
        m = iscfg & sev.eq(level)
        flag(m, f"Modif config compte", level, (cfgpath + "/" + cfgobj + " par " + user))

    # 5. Nom de compte voyou — uniquement sur op de config compte OU login réussi
    if rogue_re is not None:
        is_cfg_acc = iscfg & cfgobj.ne("")
        is_succ = ld.eq("Admin login successful") | ld.eq("SSL VPN tunnel up")
        target = cfgobj.where(is_cfg_acc, user)
        rogue = (is_cfg_acc | is_succ) & target.map(
            lambda s: bool(rogue_re.search(s)) if isinstance(s, str) else False)
        flag(rogue, "Nom de compte potentiellement voyou (SUSPICION)", "eleve", ("cible=" + target))

    # 6. Exfiltration / actions sensibles
    flag(ld.eq("Admin performed an action from GUI") & action.eq("download"),
         "Téléchargement de config via GUI", "moyen", ("par " + user + " srcip=" + srcip))
    flag(ld.eq("Log file downloaded from GUI"), "Téléchargement de logs via GUI", "faible", ("par " + user))

    # 7. Persistance (automation) — action-type non présent dans l'event log
    flag(ld.eq("Automation stitch triggered"),
         "Automation déclenchée (vérifier action-type en config)", "info", pd.Series("", index=df.index))

    # 8. Réseau : sortie boîtier non listée
    net_out = typ.eq("traffic") & sub.eq("local") & ~dstip.map(intern).fillna(False) \
        & ~dstip.isin(legit_dst) & ~dstip.isin(wan_ips) & ~dstip.isin(fortinet_dst) \
        & ~dstip.map(dst_legit_net).fillna(False) & dstip.ne("")
    flag(net_out, "Trafic sortant du boîtier vers destination non listée", "moyen", ("dstip=" + dstip))

    # 9. VPN -> management
    flag(src_vpn & dstip.isin(mgmt_ips), "Accès depuis pool VPN vers management", "eleve",
         ("srcip=" + srcip + " dstip=" + dstip))

    # 10. UTM/app-ctrl : application bloquée / risque critique / proxy non listé
    whitelist = set(cfg.get("app_ctrl_whitelist", []))
    appcat, app_name = g("appcat"), g("app")
    hostname, apprisk = g("hostname"), g("apprisk")
    utm_ac = typ.eq("utm") & sub.eq("app-ctrl")
    app_detail = "app=" + app_name + " host=" + hostname + " srcip=" + srcip

    # 10a — application explicitement bloquée par FortiGate
    flag(utm_ac & action.eq("block"),
         "Application bloquée par contrôle applicatif (UTM/app-ctrl)", "eleve", app_detail)

    # 10b — risque critique non bloqué et hors liste blanche (SUSPICION)
    not_wl = ~hostname.isin(whitelist)
    flag(utm_ac & apprisk.eq("critical") & ~action.eq("block") & not_wl,
         "Application à risque critique non bloquée (SUSPICION — UTM/app-ctrl)", "moyen", app_detail)

    # 10c — catégorie Proxy hors liste blanche (possible outil de contournement)
    flag(utm_ac & appcat.eq("Proxy") & not_wl,
         "Trafic via outil de proxy/anonymisation (UTM/app-ctrl)", "eleve", app_detail)

    # 11. Brute-force potentiellement RÉUSSI : succès précédé d'une rafale d'échecs
    #     sur la même IP/le même compte. Corrélation temporelle -> SUSPICION.
    bf = cfg.get("bruteforce", {})
    bf_win = int(bf.get("fenetre_minutes", 60))
    bf_seuil = int(bf.get("seuil_echecs", 5))
    hit, n_ech, par = _bruteforce_success_mask(df, ld, srcip, user, bf_win, bf_seuil)
    if hit.any():
        bf_detail = ("user=" + user + " srcip=" + srcip + " (" + n_ech.astype(str)
                     + " échecs/" + par + " en " + str(bf_win) + "min)")
        flag(hit & ~src_int,
             "Brute-force potentiellement réussi depuis source externe (SUSPICION)",
             "critique", bf_detail)
        flag(hit & src_int,
             "Succès admin après rafale d'échecs (interne — SUSPICION)",
             "eleve", bf_detail)

    # 12. Horaires inhabituels : login admin RÉUSSI hors plage ouvrée -> SUSPICION
    #     comportementale (faible). Tunable via `horaires_ouvres`.
    ho = cfg.get("horaires_ouvres", {})
    if ho and "timestamp" in df.columns:
        h_debut = int(ho.get("debut", 7))
        h_fin = int(ho.get("fin", 20))
        ts = df["timestamp"]
        valid_ts = ts.notna()
        hour = ts.dt.hour
        hors = (hour < h_debut) | (hour >= h_fin)
        if bool(ho.get("alerte_weekend", True)):
            hors = hors | (ts.dt.dayofweek >= 5)
        odd = ld.eq("Admin login successful") & hors & valid_ts
        quand = ts.dt.strftime("%a %d/%m %H:%M").where(valid_ts, "")
        flag(odd, "Login admin hors horaires ouvrés (SUSPICION comportementale)", "faible",
             ("user=" + user + " srcip=" + srcip + " à " + quand))

    # 13. Rafale d'échecs name_invalid par IP : brute-force sur comptes INEXISTANTS.
    #     Bruit d'Internet dans la majorité des cas — l'intérêt est le VOLUME : UN seul
    #     événement par (IP, fenêtre), porté par le premier échec de la rafale.
    bni = cfg.get("bruteforce_name_invalid", {})
    bni_win = int(bni.get("fenetre_minutes", 60))
    bni_seuil = int(bni.get("seuil_echecs", 20))
    if "timestamp" in df.columns:
        ts = df["timestamp"]
        ni = ld.eq("Admin login failed") & rs.eq("name_invalid") & srcip.ne("") & ts.notna()
        if ni.any():
            hit13 = pd.Series(False, index=df.index)
            det13 = pd.Series("", index=df.index)
            win64 = np.timedelta64(bni_win, "m")
            ndf = pd.DataFrame({"t": ts[ni], "ip": srcip[ni], "u": user[ni]}).sort_values("t")
            for ip, grp in ndf.groupby("ip"):
                t_arr = grp["t"].to_numpy()
                rows = grp.index.to_numpy()
                users_arr = grp["u"].to_numpy()
                i, n = 0, len(t_arr)
                while i < n:
                    j = int(np.searchsorted(t_arr, t_arr[i] + win64, "right"))
                    if j - i >= bni_seuil:
                        # déclenchée au seuil ; la rafale s'étend ensuite tant que les
                        # échecs s'enchaînent à moins d'une fenêtre d'écart (une campagne
                        # soutenue sur des heures = UN événement, pas un par fenêtre)
                        while j < n and t_arr[j] - t_arr[j - 1] <= win64:
                            j += 1
                        first = rows[i]
                        hit13.at[first] = True
                        h0 = pd.Timestamp(t_arr[i]).strftime("%d/%m %H:%M")
                        h1 = pd.Timestamp(t_arr[j - 1]).strftime("%d/%m %H:%M")
                        det13.at[first] = (
                            f"{j - i} tentatives name_invalid depuis {ip} entre {h0} et {h1}, "
                            f"{pd.unique(users_arr[i:j]).size} comptes distincts")
                        i = j
                    else:
                        i += 1
            lbl13 = "Rafale d'échecs sur comptes inexistants — name_invalid (SUSPICION)"
            flag(hit13 & ~src_int, lbl13, "moyen", det13)
            flag(hit13 & src_int, lbl13, "faible", det13)

    # 14. Nouveauté comportementale par compte admin : première IP source / premier
    #     pays vus pour ce compte sur la période -> info (SUSPICION comportementale).
    #     Sans état persistant P2 (comptes_vus_prev vide), « jamais vu » dégrade
    #     honnêtement en « pas vu plus tôt dans CETTE analyse » (dit dans le libellé) ;
    #     avec l'état, l'historique compte×pays des analyses précédentes s'ajoute.
    # 15. Impossible travel : 2 pays incompatibles pour un même compte en moins de
    #     `comportement.fenetre_minutes` (défaut 60) -> eleve (SUSPICION). Nécessite la
    #     géo ; sans base, silencieusement absente (mention dans analysis.py, comme géo).
    comptes_vus_courant: dict = {}
    ip_new = pd.Series(False, index=df.index)
    pays_new = pd.Series(False, index=df.index)
    pays_col = pd.Series("", index=df.index)
    travel_hit = pd.Series(False, index=df.index)
    travel_detail = pd.Series("", index=df.index)
    if ok.any() and "timestamp" in df.columns:
        ts = df["timestamp"]
        odf = pd.DataFrame({"t": ts[ok], "u": user[ok], "ip": srcip[ok]}) \
            .dropna(subset=["t"]).sort_values("t")
        geo_on = enricher is not None and getattr(enricher, "available", False)
        _pays_cache: dict = {}

        def _pays(ip):
            if not geo_on or not ip:
                return ""
            if ip not in _pays_cache:
                _pays_cache[ip] = enricher.lookup(ip).get("pays") or ""
            return _pays_cache[ip]

        travel_win = pd.Timedelta(
            minutes=int((cfg.get("comportement") or {}).get("fenetre_minutes", 60)))
        ips_vues, pays_vus, fenetre_travel = {}, {}, {}
        for i, t, u, ip in zip(odf.index, odf["t"], odf["u"], odf["ip"]):
            if not u:
                continue
            ips_c = ips_vues.setdefault(u, set())
            if ip and ip not in ips_c:
                ip_new.at[i] = True
            ips_c.add(ip)

            p = _pays(ip)
            if not p:
                continue
            pays_c = pays_vus.setdefault(u, set())
            pays_hist = set((comptes_vus_prev or {}).get(u, []))
            if p not in pays_c and p not in pays_hist:
                pays_new.at[i] = True
                pays_col.at[i] = p
            pays_c.add(p)
            if p not in comptes_vus_courant.setdefault(u, []):
                comptes_vus_courant[u].append(p)

            buf = fenetre_travel.setdefault(u, [])
            buf[:] = [(tt, pp) for tt, pp in buf if t - tt <= travel_win]
            conflit = next(((tt, pp) for tt, pp in buf if pp != p), None)
            if conflit:
                travel_hit.at[i] = True
                ecart = int((t - conflit[0]).total_seconds() // 60)
                travel_detail.at[i] = f"{conflit[1]} -> {p} en {ecart} min"
            buf.append((t, p))

        flag(ip_new,
             "Connexion admin depuis une IP non vue plus tôt dans cette analyse (SUSPICION comportementale)",
             "info", ("user=" + user + " srcip=" + srcip))
        if comptes_vus_prev:
            regle_pays = ("Connexion admin depuis un pays jamais vu pour ce compte, "
                          "historique inclus (SUSPICION comportementale)")
        else:
            regle_pays = ("Connexion admin depuis un pays non vu plus tôt dans cette analyse "
                          "(SUSPICION comportementale)")
        flag(pays_new, regle_pays, "info", ("user=" + user + " srcip=" + srcip + " pays=" + pays_col))
        flag(travel_hit,
             "Connexions admin depuis pays incompatibles en fenêtre courte — impossible travel (SUSPICION)",
             "eleve", ("user=" + user + " srcip=" + srcip + " (" + travel_detail + ")"))

    if not parts:
        out = df.iloc[0:0].assign(regle="", severite="", detail="", mitre="", sev_rank=0)
    else:
        out = pd.concat(parts)
        out["mitre"] = out["regle"].map(MITRE_MAP).fillna("")  # indicatif ; règle inconnue -> vide
        out["sev_rank"] = out["severite"].map(SEV_ORDER).fillna(0).astype(int)
        out = out.sort_values("sev_rank", ascending=False)
    out.attrs["comportement_vus_courant"] = comptes_vus_courant
    return out
