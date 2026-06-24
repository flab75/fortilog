"""Point d'entrée CLI : orchestre ingestion -> parsing -> normalisation -> détection -> comparaison -> sorties."""
from __future__ import annotations
import argparse
from pathlib import Path
import pandas as pd
import yaml

from . import ingest, normalize, detect, compare, correlate, report, excel, geo
from .validate import validate_config

TARGET_COLS = ["date", "time", "tz", "eventtime", "logid", "type", "subtype",
               "level", "logdesc", "user", "ui", "method", "srcip", "dstip",
               "srcport", "dstport", "action", "status", "reason", "group",
               "cfgpath", "cfgobj", "cfgattr", "remip", "tunnelip", "tunneltype",
               "service", "sentbyte", "rcvdbyte", "msg",
               # utm/app-ctrl
               "appid", "appcat", "app", "hostname", "apprisk", "direction", "policyid",
               # event/security-rating
               "auditscore", "criticalcount", "highcount", "mediumcount",
               "lowcount", "passedcount", "auditreporttype", "auditid"]


def load_file(path: Path) -> pd.DataFrame:
    keep = set(TARGET_COLS)
    recs = []
    with open(path, errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            d = ingest.parse_line(line)
            recs.append({k: d.get(k, "") for k in keep})  # colonnes utiles seulement
    df = pd.DataFrame.from_records(recs, columns=TARGET_COLS)
    df["source_file"] = path.name
    return df


def run(input_dir, config_path, output_dir):
    cfg = yaml.safe_load(Path(config_path).read_text())
    errors = validate_config(cfg)
    if errors:
        msg = "Configuration invalide :\n" + "\n".join(f"  - {e}" for e in errors)
        raise SystemExit(msg)
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    files = ingest.list_log_files(input_dir)
    if not files:
        raise SystemExit(f"Aucun fichier .log dans {input_dir}")

    parts, meta_files = [], []
    for f in files:
        t, s, reconnu = ingest.detect_type(f)
        df = load_file(f)
        df["type"] = df["type"].replace("", t)
        df["subtype"] = df["subtype"].replace("", s)
        meta_files.append({"name": f.name, "type": t, "subtype": s,
                           "reconnu": reconnu, "rows": len(df)})
        parts.append(df)
    full = pd.concat(parts, ignore_index=True)

    full["timestamp"] = normalize.build_timestamp(full)
    full["boitier"] = normalize.assign_boitier(full, cfg.get("boitiers", {}), cfg.get("fichiers_boitier"))
    full = normalize.deduplicate(full)

    # Optimisation mémoire : colonnes à faible cardinalité -> category
    for c in ["type", "subtype", "level", "logdesc", "action", "status",
              "reason", "boitier", "source_file"]:
        if c in full.columns:
            full[c] = full[c].astype("category")

    events = detect.run_detection(full, cfg)
    chains = correlate.correlate_chains(events, cfg)

    # Enrichissement géo/ASN + réputation (hors-ligne, dégradation honnête si pas de base)
    enricher = geo.load_enricher(cfg)
    repdb = geo.load_reputation(cfg)
    if not events.empty:
        events = geo.enrich_events(events, cfg, enricher, repdb)
    sources_ext = geo.top_external_sources(full, cfg, enricher,
                                           n=int(cfg.get("top_sources_externes", 50)))
    reputation = geo.reputation_sources(full, cfg, repdb, enricher)

    # Bilan hardening : lignes security-rating (rapport texte uniquement)
    _sr_mask = (full["type"].astype(str).eq("event") &
                full["subtype"].astype(str).eq("security-rating") &
                full["logdesc"].astype(str).eq("Security Rating summary"))
    _sr_cols = [c for c in ["timestamp", "boitier", "logdesc", "auditscore", "criticalcount",
                             "highcount", "mediumcount", "lowcount", "passedcount", "auditreporttype"]
                if c in full.columns]
    security_rating = (full.loc[_sr_mask, _sr_cols].copy()
                       if _sr_mask.any() else pd.DataFrame(columns=_sr_cols))

    agg = compare.aggregate(full, bucket="day")
    bursts = compare.detect_bursts(full, cfg)

    # différentiels : entre jours (par boîtier) + entre boîtiers
    diffs = []
    for boitier, g in full.groupby("boitier"):
        days = sorted(g["timestamp"].dropna().dt.date.unique())
        for a, b in zip(days, days[1:]):
            da = g[g["timestamp"].dt.date == a]
            db = g[g["timestamp"].dt.date == b]
            d = compare.diff_entities(da, db, f"{boitier} {a}", f"{boitier} {b}")
            if not d.empty:
                diffs.append(d)
    boits = [b for b in full["boitier"].unique() if b != "inconnu"]
    if len(boits) >= 2:
        d = compare.diff_entities(full[full.boitier == boits[0]],
                                  full[full.boitier == boits[1]], boits[0], boits[1])
        if not d.empty:
            diffs.append(d)
    diff = pd.concat(diffs, ignore_index=True) if diffs else pd.DataFrame()

    EVENT_COLS = ["timestamp", "boitier", "severite", "regle", "detail", "logdesc",
                  "user", "ui", "srcip", "srcip_portee", "srcip_pays", "srcip_asn",
                  "srcip_reputation", "dstip", "action", "status", "reason", "source_file"]
    events_slim = events[[c for c in EVENT_COLS if c in events.columns]] if not events.empty else events

    MAX_UNIFIE = int(cfg.get("max_lignes_donnees_unifiees", 200000))
    unifie_cols = [c for c in TARGET_COLS if c in full.columns] + ["boitier", "timestamp", "source_file"]
    unifie = full[unifie_cols]
    unifie_tronque = len(unifie) > MAX_UNIFIE
    if unifie_tronque:
        unifie = unifie.sort_values("timestamp").tail(MAX_UNIFIE)

    EVENT_COLS = ["timestamp", "boitier", "severite", "regle", "detail", "logdesc",
                  "user", "ui", "srcip", "srcip_portee", "srcip_pays", "srcip_asn",
                  "srcip_reputation", "dstip", "action", "status", "reason", "source_file"]
    events_slim = events[[c for c in EVENT_COLS if c in events.columns]] if not events.empty else events

    ref_rows = [{"clé": k, "valeur": str(v)} for k, v in cfg.items()]
    if unifie_tronque:
        ref_rows.append({"clé": "AVERTISSEMENT", "valeur":
                         f"Feuille 'Donnees unifiees' tronquée aux {MAX_UNIFIE} derniers événements "
                         f"(total {len(full)}). Les agrégats/détections portent sur la TOTALITÉ."})
    tables = {
        "unifie": unifie,
        "events": events_slim.reset_index(drop=True) if not events.empty else events,
        "chains": chains,
        "agg": agg, "bursts": bursts, "diff": diff,
        "security_rating": security_rating,
        "sources_externes": sources_ext,
        "reputation": reputation,
        "ref": pd.DataFrame(ref_rows),
    }
    meta = {"n_files": len(files), "n_rows": len(full),
            "dedup": full.attrs.get("dedup_removed", 0), "files": meta_files,
            "geo_available": enricher.available,
            "reputation_available": repdb.available}

    xlsx_path = out / "rapport_fortigate.xlsx"
    excel.write_workbook(str(xlsx_path), tables, cfg)
    txt = report.build_report(tables, meta)
    (out / "rapport_fortigate.txt").write_text(txt)
    print(txt)
    print(f"\n>> Classeur : {xlsx_path}")
    return tables, meta


def main():
    ap = argparse.ArgumentParser(description="Analyseur de logs FortiGate")
    ap.add_argument("--input", required=True, help="dossier des fichiers .log")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--output", default="./rapport")
    a = ap.parse_args()
    run(a.input, a.config, a.output)


if __name__ == "__main__":
    main()
