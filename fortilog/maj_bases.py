# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mise à jour des bases hors-ligne (géo/ASN/réputation/plages Fortinet).

Étape RÉSEAU, distincte de l'analyse : l'analyse reste 100 % hors-ligne et lit les
fichiers locaux. Ce module ne télécharge une base QUE si elle est périmée selon le
rythme de son producteur (réglable dans `bases.maj` du config.yaml) :

    réputation (FireHOL…)  > `reputation_jours` (défaut 1)    — publiée chaque jour
    ASN (iptoasn)          > `asn_jours`        (défaut 7)    — quotidienne, bouge peu (30 Mo)
    pays (DB-IP Lite)      nouveau fichier MENSUEL publié     — sinon on garde le mois en place
    plages Fortinet (ARIN) > `fortinet_jours`   (défaut 180)  — registre, change rarement

Garde-fous (dégradation honnête) :
- téléchargement dans un fichier temporaire, contrôle du FORMAT et d'un nombre minimal
  de lignes, puis remplacement atomique — une page d'erreur HTML ou un fichier tronqué
  n'écrase jamais une base valide ;
- réseau absent / erreur → l'ancienne base est conservée, l'échec est signalé, l'analyse
  continue (jamais bloquant) ;
- une liste de réputation sans `url` dans le config n'est pas mise à jour (on ne devine
  pas sa source) : elle est signalée « sans source ».

Usage :
    python -m fortilog.maj_bases [--config config.yaml] [--force]
"""
from __future__ import annotations
import argparse
import datetime as _dt
import gzip
import ipaddress
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


from . import fetch_fortinet_ranges
from .common import load_config, default_config_path

GEO_URL = "https://download.db-ip.com/free/dbip-country-lite-{mois}.csv.gz"
ASN_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
DEFAUTS = {"reputation_jours": 1, "asn_jours": 7, "fortinet_jours": 180, "timeout_s": 60}
# Nombre minimal de lignes valides pour accepter un téléchargement (ordres de grandeur
# réels : DB-IP ~700k, iptoasn ~500k, FireHOL L1 ~4k, Fortinet ~26).
MIN_LIGNES = {"geo": 100_000, "asn": 100_000, "netset": 100}
UA = "fortilog/maj-bases"

A_JOUR, MAJ, ECHEC, SANS_SOURCE = "à jour", "mise à jour", "échec", "sans source"


# ── Contrôle de format ────────────────────────────────────────────────────────

def _ip_ok(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


def _net_ok(s: str) -> bool:
    try:
        ipaddress.ip_network(s.strip(), strict=False)
        return True
    except ValueError:
        return False


def compter_lignes_valides(path: Path, kind: str) -> int:
    """Nombre de lignes au format attendu (`geo` : ip,ip,pays ; `asn` : TSV 5 champs ;
    `netset` : un CIDR/IP par ligne, `#` = commentaire). Les autres lignes sont ignorées."""
    n = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if kind == "geo":
                f = line.split(",")
                ok = len(f) >= 3 and _ip_ok(f[0]) and _ip_ok(f[1])
            elif kind == "asn":
                f = line.split("\t")
                ok = len(f) >= 5 and _ip_ok(f[0]) and _ip_ok(f[1])
            else:
                ok = _net_ok(line.split()[0])
            n += ok
    return n


# ── Téléchargement + remplacement atomique ────────────────────────────────────

def _telecharger(url: str, dest: Path, timeout: int) -> None:
    """Télécharge `url` vers `dest` (décompresse si .gz). Lève en cas d'erreur HTTP."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        src = gzip.GzipFile(fileobj=resp) if url.endswith(".gz") else resp
        with open(dest, "wb") as out:
            shutil.copyfileobj(src, out, 1 << 20)


def _remplacer(tmp: Path, path: Path) -> None:
    """Remplacement atomique en gardant les droits du fichier en place (mkstemp crée en
    0600 ; sans cela la base deviendrait illisible pour les autres comptes)."""
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        mode = 0o644
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _installer(url: str, path: Path, kind: str, timeout: int, min_lignes: int) -> int:
    """Télécharge dans un temporaire du MÊME dossier, contrôle, puis remplace `path`.
    Renvoie le nombre de lignes valides. Lève ValueError si le contrôle échoue (la base
    en place n'est alors pas touchée)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    os.close(fd)
    tmp = Path(tmp)
    try:
        _telecharger(url, tmp, timeout)
        n = compter_lignes_valides(tmp, kind)
        if n < min_lignes:
            raise ValueError(f"fichier reçu non conforme ({n} ligne(s) valide(s), "
                             f"minimum attendu {min_lignes}) — base en place conservée")
        _remplacer(tmp, path)
        return n
    finally:
        tmp.unlink(missing_ok=True)


def _sidecar(path: Path) -> Path:
    return path.with_name(path.name + ".maj.json")


def _lire_sidecar(path: Path) -> dict:
    try:
        return json.loads(_sidecar(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _ecrire_sidecar(path: Path, url: str, n: int) -> None:
    info = {"source": url, "date_maj": _dt.datetime.now().isoformat(timespec="seconds"),
            "lignes_valides": n}
    try:
        _sidecar(path).write_text(json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass   # traçabilité de confort : son absence n'invalide pas la base


def _age_jours(path: Path) -> float | None:
    if not path.exists():
        return None
    return (time.time() - path.stat().st_mtime) / 86400


def _res(nom, path, statut, detail="") -> dict:
    return {"nom": nom, "path": str(path), "statut": statut, "detail": detail}


# ── Une fonction par famille de base ──────────────────────────────────────────

def _maj_simple(nom, path, url, kind, seuil_jours, timeout, force, min_lignes):
    """Base à URL fixe (iptoasn, listes de réputation) : rafraîchie au-delà de N jours."""
    age = _age_jours(path)
    if not force and age is not None and age <= seuil_jours:
        return _res(nom, path, A_JOUR, f"{int(age)} j (seuil {seuil_jours:g} j)")
    try:
        n = _installer(url, path, kind, timeout, min_lignes)
    except Exception as e:
        return _res(nom, path, ECHEC, f"{type(e).__name__} : {e}")
    _ecrire_sidecar(path, url, n)
    return _res(nom, path, MAJ, f"{n:,} lignes depuis {url}")


def _mois(d: _dt.date, decalage: int = 0) -> str:
    m = d.year * 12 + (d.month - 1) + decalage
    return f"{m // 12:04d}-{m % 12 + 1:02d}"


def _mois_local(path: Path) -> str | None:
    """Mois des données en place : celui de la source enregistrée, sinon celui du mtime."""
    m = re.search(r"(\d{4}-\d{2})\.csv", _lire_sidecar(path).get("source", ""))
    if m:
        return m.group(1)
    if path.exists():
        return _dt.date.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m")
    return None


def _maj_geo(nom, path, url_tpl, timeout, force, today=None):
    """DB-IP Lite est MENSUEL : on vise le fichier du mois courant ; s'il n'est pas encore
    publié (404 en tout début de mois), celui du mois précédent — seulement s'il est plus
    récent que les données en place."""
    today = today or _dt.date.today()
    courant = _mois(today)
    local = _mois_local(path)
    erreurs = []
    for mois in (courant, _mois(today, -1)):
        if not force and local is not None and local >= mois:
            note = "" if mois == courant else f" (celui de {courant} pas encore publié)"
            return _res(nom, path, A_JOUR, f"fichier du mois {local}{note}")
        url = url_tpl.format(mois=mois)
        try:
            n = _installer(url, path, "geo", timeout, MIN_LIGNES["geo"])
        except urllib.error.HTTPError as e:
            erreurs.append(f"{mois} : HTTP {e.code}")
            continue
        except Exception as e:
            return _res(nom, path, ECHEC, f"{type(e).__name__} : {e}")
        _ecrire_sidecar(path, url, n)
        return _res(nom, path, MAJ, f"{n:,} lignes, fichier du mois {mois}")
    return _res(nom, path, ECHEC, "aucun fichier publié trouvé (" + ", ".join(erreurs)
                + ") — base en place conservée")


def _maj_fortinet(nom, path, seuil_jours, timeout, force):
    """Plages Fortinet : régénérées depuis ARIN (réutilise fetch_fortinet_ranges)."""
    age = _age_jours(path)
    if not force and age is not None and age <= seuil_jours:
        return _res(nom, path, A_JOUR, f"{int(age)} j (seuil {seuil_jours:g} j)")
    org = fetch_fortinet_ranges.DEFAULT_ORG
    try:
        cidrs = fetch_fortinet_ranges.to_cidrs(fetch_fortinet_ranges.fetch_netrefs(org, timeout))
        if not cidrs:
            raise ValueError(f"aucune plage renvoyée par ARIN pour {org} — fichier en place conservé")
        fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(fetch_fortinet_ranges.render(cidrs, org))
        _remplacer(Path(tmp), path)
    except Exception as e:
        return _res(nom, path, ECHEC, f"{type(e).__name__} : {e}")
    return _res(nom, path, MAJ, f"{len(cidrs)} plage(s) depuis ARIN ({org})")


# ── Point d'entrée ────────────────────────────────────────────────────────────

def mettre_a_jour(cfg: dict, force: bool = False, today: _dt.date | None = None) -> list[dict]:
    """Met à jour les bases configurées qui sont périmées. Ne lève jamais : chaque base
    renvoie `{nom, path, statut, detail}` avec statut ∈ {à jour, mise à jour, échec,
    sans source}. Une base absente du config n'est pas gérée (pas d'enrichissement demandé)."""
    p = {**DEFAUTS, **((cfg.get("bases") or {}).get("maj") or {})}
    timeout = int(p["timeout_s"])
    out = []
    if cfg.get("geo_db_path"):
        out.append(_maj_geo("Géo (pays)", Path(cfg["geo_db_path"]),
                            p.get("geo_url", GEO_URL), timeout, force, today))
    if cfg.get("asn_db_path"):
        out.append(_maj_simple("ASN", Path(cfg["asn_db_path"]), p.get("asn_url", ASN_URL),
                               "asn", float(p["asn_jours"]), timeout, force, MIN_LIGNES["asn"]))
    if cfg.get("fortinet_ranges_file"):
        out.append(_maj_fortinet("Plages Fortinet", Path(cfg["fortinet_ranges_file"]),
                                 float(p["fortinet_jours"]), timeout, force))
    for entry in cfg.get("reputation_lists") or []:
        if isinstance(entry, str):
            entry = {"path": entry}
        nom = entry.get("nom", entry.get("path", "?"))
        path = Path(entry.get("path", ""))
        if not entry.get("url"):
            out.append(_res(nom, path, SANS_SOURCE, "pas de clé `url` dans reputation_lists"))
            continue
        out.append(_maj_simple(nom, path, entry["url"], "netset", float(p["reputation_jours"]),
                               timeout, force, int(entry.get("min_lignes", MIN_LIGNES["netset"]))))
    return out


def resume(resultats: list[dict]) -> list[str]:
    """Une ligne lisible par base (CLI, UI)."""
    icone = {A_JOUR: "✓", MAJ: "⬇", ECHEC: "⚠", SANS_SOURCE: "–"}
    return [f"{icone.get(r['statut'], '?')} {r['nom']} : {r['statut']}"
            + (f" — {r['detail']}" if r["detail"] else "") for r in resultats]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Met à jour les bases géo/ASN/réputation/Fortinet "
                                             "périmées (seule étape réseau de fortilog).")
    ap.add_argument("--config", default=None,
                    help="référentiel (défaut : ./config.yaml, sinon celui du projet)")
    ap.add_argument("--force", action="store_true",
                    help="retélécharge même les bases à jour")
    a = ap.parse_args(argv)
    cfg = load_config(a.config or default_config_path())
    res = mettre_a_jour(cfg, force=a.force)
    for line in resume(res):
        print(line)
    return 1 if any(r["statut"] == ECHEC for r in res) else 0


if __name__ == "__main__":
    raise SystemExit(main())
