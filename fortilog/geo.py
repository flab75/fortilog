# SPDX-License-Identifier: AGPL-3.0-or-later
"""Enrichissement géo/ASN des IP — 100 % HORS-LIGNE, aucune requête réseau.

Principe directeur : c'est du CONTEXTE, pas un verdict. Une IP « hébergeur au
pays X » n'est ni une preuve ni une absolution. Si aucune base locale n'est
configurée, l'enrichissement se dégrade proprement (colonnes vides + mention
honnête) — on n'invente jamais un pays ni un ASN.

Bases supportées (formats à plages, license-clean, à fournir par l'utilisateur) :
- Pays  : DB-IP Lite Country CSV  -> `start_ip,end_ip,country_code`
          (CC-BY-4.0, https://db-ip.com/db/download/ip-to-country-lite)
- ASN   : iptoasn ip2asn-v4.tsv   -> `start_ip\tend_ip\tasn\tcountry\torg`
          (domaine public, https://iptoasn.com/)

Aucune dépendance externe : lecture CSV/TSV + recherche dichotomique (bisect)
sur des plages d'entiers IPv4. IPv6 -> portée seulement (géo/ASN laissés vides).
"""
from __future__ import annotations
import bisect
import csv
import ipaddress
from pathlib import Path

import pandas as pd

# Valeurs de portée (scope) — calculables SANS aucune base.
INTERNE = "interne"
EXTERNE = "externe"
RESERVE = "reserve"
INVALIDE = "invalide"


def _ip_to_int(ip: str) -> int | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version != 4:
        return None
    return int(a)


def classify_scope(ip: str, nets: list) -> str:
    """Portée d'une IP vis-à-vis du référentiel interne. Ne nécessite aucune base.
    nets = liste d'ip_network (plages_internes du config)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return INVALIDE
    if any(a in n for n in nets):
        return INTERNE
    if a.is_global:
        return EXTERNE
    return RESERVE  # privé hors référentiel, loopback, réservé, multicast…


class RangeTable:
    """Table de plages IPv4 -> charge utile, interrogée par dichotomie."""

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._ends: list[int] = []
        self._payload: list[tuple] = []

    def __len__(self) -> int:
        return len(self._starts)

    @classmethod
    def from_cidr_file(cls, path) -> "RangeTable":
        """Charge une liste de réputation : un CIDR ou une IP par ligne, `#` = commentaire.
        Formats type FireHOL/.netset/.ipset. IPv6 et lignes illisibles ignorés."""
        t = cls()
        rows = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.split("#")[0].split(";")[0].strip()
                if not line:
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                except ValueError:
                    continue
                if net.version != 4:
                    continue
                rows.append((int(net.network_address), int(net.broadcast_address), ()))
        rows.sort(key=lambda r: r[0])
        t._starts = [r[0] for r in rows]
        t._ends = [r[1] for r in rows]
        t._payload = [r[2] for r in rows]
        return t

    @classmethod
    def from_file(cls, path, delimiter: str, payload_cols: tuple[int, ...]) -> "RangeTable":
        """Charge un fichier à plages. Colonnes 0/1 = start_ip/end_ip (dotted),
        payload_cols = indices des colonnes de charge utile. Lignes illisibles ignorées."""
        t = cls()
        rows = []
        with open(path, encoding="utf-8", errors="replace", newline="") as fh:
            for parts in csv.reader(fh, delimiter=delimiter):
                if len(parts) <= max(1, *payload_cols):
                    continue
                s = _ip_to_int(parts[0].strip())
                e = _ip_to_int(parts[1].strip())
                if s is None or e is None or e < s:
                    continue
                rows.append((s, e, tuple(parts[c].strip() for c in payload_cols)))
        rows.sort(key=lambda r: r[0])
        t._starts = [r[0] for r in rows]
        t._ends = [r[1] for r in rows]
        t._payload = [r[2] for r in rows]
        return t

    def lookup(self, ip: str) -> tuple | None:
        n = _ip_to_int(ip)
        if n is None or not self._starts:
            return None
        i = bisect.bisect_right(self._starts, n) - 1
        if i >= 0 and n <= self._ends[i]:
            return self._payload[i]
        return None


class GeoEnricher:
    """Agrège base pays + base ASN. `available` = au moins une base chargée."""

    def __init__(self, country: RangeTable | None, asn: RangeTable | None) -> None:
        self.country = country
        self.asn = asn

    @property
    def available(self) -> bool:
        return bool(self.country) or bool(self.asn)

    def lookup(self, ip: str) -> dict:
        """Renvoie {pays, asn, org} pour une IP (valeurs vides si non trouvées)."""
        pays = asn = org = ""
        if self.country is not None:
            r = self.country.lookup(ip)
            if r:
                pays = r[0]
        if self.asn is not None:
            r = self.asn.lookup(ip)
            if r:
                asn = r[0]
                org = r[1] if len(r) > 1 else ""
        return {"pays": pays, "asn": asn, "org": org}


def load_enricher(cfg: dict) -> GeoEnricher:
    """Construit l'enrichisseur depuis le config. Toute base absente/illisible ->
    ignorée silencieusement (dégradation honnête, jamais d'erreur fatale)."""
    country = asn = None
    cpath = cfg.get("geo_db_path")
    if cpath and Path(cpath).is_file():
        try:
            country = RangeTable.from_file(cpath, delimiter=",", payload_cols=(2,))
        except Exception:
            country = None
    apath = cfg.get("asn_db_path")
    if apath and Path(apath).is_file():
        try:
            # ip2asn-v4.tsv : start, end, asn(2), country(3), org(4)
            asn = RangeTable.from_file(apath, delimiter="\t", payload_cols=(2, 4))
        except Exception:
            asn = None
    return GeoEnricher(country, asn)


class ReputationDB:
    """Listes de réputation (threat intel) HORS-LIGNE. `match(ip)` renvoie les noms
    des listes contenant l'IP. C'est un SIGNAL fort, mais une présence en liste reste
    à confirmer (faux positifs possibles, listes parfois larges)."""

    def __init__(self, lists: list) -> None:
        self._lists = lists  # [(nom, RangeTable), ...]

    @property
    def available(self) -> bool:
        return any(len(t) for _, t in self._lists)

    def match(self, ip: str) -> list:
        return [nom for nom, t in self._lists if t.lookup(ip) is not None]


def load_reputation(cfg: dict) -> ReputationDB:
    """Construit la base de réputation depuis `reputation_lists` du config.
    Chaque entrée = {nom, path} (ou un simple chemin). Liste absente -> ignorée."""
    lists = []
    for entry in (cfg.get("reputation_lists") or []):
        if isinstance(entry, dict):
            path = entry.get("path")
            nom = entry.get("nom") or (Path(path).name if path else "?")
        else:
            path = entry
            nom = Path(str(entry)).name
        if path and Path(path).is_file():
            try:
                lists.append((nom, RangeTable.from_cidr_file(path)))
            except Exception:
                continue
    return ReputationDB(lists)


def _nets(cfg: dict) -> list:
    out = []
    for c in cfg.get("plages_internes", []):
        try:
            out.append(ipaddress.ip_network(str(c).split("#")[0].strip()))
        except ValueError:
            continue
    return out


def enrich_events(events, cfg: dict, enricher: GeoEnricher | None = None,
                  repdb: ReputationDB | None = None):
    """Ajoute aux événements : srcip_portee (toujours) + srcip_pays/asn/org (si base géo)
    + srcip_reputation (si listes de réputation). N'altère aucune colonne existante."""
    if events is None or events.empty or "srcip" not in events.columns:
        return events
    if enricher is None:
        enricher = load_enricher(cfg)
    if repdb is None:
        repdb = load_reputation(cfg)
    nets = _nets(cfg)
    df = events.copy()

    uniq = df["srcip"].fillna("").astype(str).unique()
    scope_map = {ip: classify_scope(ip, nets) for ip in uniq}
    df["srcip_portee"] = df["srcip"].map(scope_map)

    if enricher.available:
        # n'interroge la base que pour les IP externes (les seules pertinentes)
        geo_map = {ip: (enricher.lookup(ip) if scope_map.get(ip) == EXTERNE
                        else {"pays": "", "asn": "", "org": ""}) for ip in uniq}
        df["srcip_pays"] = df["srcip"].map(lambda ip: geo_map.get(ip, {}).get("pays", ""))
        df["srcip_asn"] = df["srcip"].map(lambda ip: geo_map.get(ip, {}).get("asn", ""))
        df["srcip_org"] = df["srcip"].map(lambda ip: geo_map.get(ip, {}).get("org", ""))
    if repdb.available:
        # réputation EXTERNE uniquement : les listes type FireHOL incluent les bogons
        # (10/8, 192.168/16…) -> matcher une IP interne serait un faux positif.
        rep_map = {ip: (", ".join(repdb.match(ip)) if scope_map.get(ip) == EXTERNE else "")
                   for ip in uniq}
        df["srcip_reputation"] = df["srcip"].map(rep_map)
    return df


def reputation_sources(full, cfg: dict, repdb: ReputationDB | None = None,
                       enricher: GeoEnricher | None = None):
    """IP sources présentes dans une liste de réputation (threat intel) ayant touché
    le pare-feu : srcip, listes, volume, logins échoués, géo/ASN. Signal fort — mais
    une présence en liste reste À CONFIRMER (faux positifs/listes larges possibles)."""
    cols = ["srcip", "listes", "srcip_pays", "srcip_asn", "srcip_org",
            "occurrences", "logins_echoues"]
    if full is None or full.empty or "srcip" not in full.columns:
        return pd.DataFrame(columns=cols)
    if repdb is None:
        repdb = load_reputation(cfg)
    if not repdb.available:
        return pd.DataFrame(columns=cols)
    if enricher is None:
        enricher = load_enricher(cfg)

    src = full["srcip"].fillna("").astype(str)
    uniq = src.unique()
    nets = _nets(cfg)
    # EXTERNE uniquement : éviter les faux positifs sur les bogons (10/8…) des listes
    match_map = {ip: repdb.match(ip) for ip in uniq
                 if ip and classify_scope(ip, nets) == EXTERNE}
    bad = {ip for ip, m in match_map.items() if m}
    mask = src.isin(bad)
    if not mask.any():
        return pd.DataFrame(columns=cols)

    ld = full.get("logdesc")
    failed = (ld.fillna("").astype(str).eq("Admin login failed")
              if ld is not None else pd.Series(False, index=full.index))
    g = pd.DataFrame({"srcip": src[mask], "failed": failed[mask].astype(int)})
    agg = (g.groupby("srcip")
             .agg(occurrences=("srcip", "size"), logins_echoues=("failed", "sum"))
             .reset_index()
             .sort_values("occurrences", ascending=False))
    agg["listes"] = agg["srcip"].map(lambda ip: ", ".join(match_map.get(ip, [])))
    if enricher.available:
        looks = agg["srcip"].map(enricher.lookup)
        agg["srcip_pays"] = [d.get("pays", "") for d in looks]
        agg["srcip_asn"] = [d.get("asn", "") for d in looks]
        agg["srcip_org"] = [d.get("org", "") for d in looks]
    else:
        agg["srcip_pays"] = agg["srcip_asn"] = agg["srcip_org"] = ""
    return agg[cols].reset_index(drop=True)


def _infra_ips(cfg: dict) -> set:
    """IP d'infrastructure connue (à exclure du classement des sources externes) :
    WAN/mgmt des boîtiers + destinations légitimes (peers IPsec, logging, DNS…).
    Ce sont des IP externes LÉGITIMES, pas des attaquants."""
    out: set = set()
    for b in cfg.get("boitiers", {}).values():
        if isinstance(b, dict):
            for f in ("wan", "mgmt"):
                if b.get(f):
                    out.add(str(b[f]))
    dests = cfg.get("destinations_legitimes", {})
    if isinstance(dests, dict):
        for ips in dests.values():
            if isinstance(ips, list):
                out.update(str(i) for i in ips)
    return out


def top_external_sources(full, cfg: dict, enricher: GeoEnricher | None = None, n: int = 50):
    """Classe les IP sources EXTERNES par volume (toutes lignes + logins échoués),
    enrichies portée/pays/ASN. Surface les sources d'attaque que les events ne
    listent pas (un brute-force `name_invalid` n'est pas une détection R2).
    Exclut l'infrastructure connue (WAN/mgmt des boîtiers, peers/DNS légitimes)."""
    cols = ["srcip", "srcip_portee", "srcip_pays", "srcip_asn", "srcip_org",
            "occurrences", "logins_echoues"]
    if full is None or full.empty or "srcip" not in full.columns:
        return pd.DataFrame(columns=cols)
    if enricher is None:
        enricher = load_enricher(cfg)
    nets = _nets(cfg)
    infra = _infra_ips(cfg)

    src = full["srcip"].fillna("").astype(str)
    scope = src.map(lambda ip: classify_scope(ip, nets))
    ext_mask = scope.eq(EXTERNE) & ~src.isin(infra)
    if not ext_mask.any():
        return pd.DataFrame(columns=cols)

    ld = full.get("logdesc")
    failed = (ld.fillna("").astype(str).eq("Admin login failed")
              if ld is not None else pd.Series(False, index=full.index))

    g = pd.DataFrame({"srcip": src[ext_mask], "failed": failed[ext_mask].astype(int)})
    agg = (g.groupby("srcip")
             .agg(occurrences=("srcip", "size"), logins_echoues=("failed", "sum"))
             .reset_index()
             .sort_values("occurrences", ascending=False)
             .head(n))

    agg["srcip_portee"] = EXTERNE
    if enricher.available:
        looks = agg["srcip"].map(enricher.lookup)
        agg["srcip_pays"] = [d.get("pays", "") for d in looks]
        agg["srcip_asn"] = [d.get("asn", "") for d in looks]
        agg["srcip_org"] = [d.get("org", "") for d in looks]
    else:
        agg["srcip_pays"] = agg["srcip_asn"] = agg["srcip_org"] = ""
    return agg[cols].reset_index(drop=True)
