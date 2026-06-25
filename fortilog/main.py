"""Point d'entrée CLI : orchestre ingestion -> parsing -> normalisation -> détection -> comparaison -> sorties."""
from __future__ import annotations
import argparse
from pathlib import Path
import pandas as pd
import yaml

from . import ingest, normalize, detect, compare, correlate, report, excel, geo, confaudit, confdiff, analysis
from .ingest import TARGET_COLS, load_file  # réexport (API utilisée par les tests/confdiff)
from .validate import validate_config


def _emit(out, tables, meta, cfg):
    """Calcule la synthèse, écrit le classeur Excel + le rapport texte, renvoie (tables, meta)."""
    rapport = analysis.build_analysis(tables, meta, cfg)
    meta["analysis"] = rapport
    xlsx_path = out / "rapport_fortigate.xlsx"
    excel.write_workbook(str(xlsx_path), tables, cfg, analysis_text=rapport)
    txt = rapport + "\n\n" + ("=" * 70) + "\n" + report.build_report(tables, meta)
    (out / "rapport_fortigate.txt").write_text(txt)
    print(txt)
    print(f"\n>> Classeur : {xlsx_path}")
    return tables, meta


def _compute_config_diff(ref_conf, conf_files, logs_dir, cfg, boitier_for):
    """Compare chaque .conf courant à une config de RÉFÉRENCE (validée), avec
    attribution qui/quand via les logs. Renvoie un DataFrame (vide si pas de référence).
    Colonnes alignées sur la sortie réelle (diff_configs + attribute_changes + inserts)."""
    cols = ["boitier", "fichier", "section", "objet", "statut", "changements",
            "criticite", "auteur", "quand", "action_log"]
    if not ref_conf or not conf_files:
        return pd.DataFrame(columns=cols)
    ref_text = Path(ref_conf).read_text(errors="replace")
    change_ev = confdiff.load_change_events(logs_dir, cfg) if logs_dir else pd.DataFrame()
    parts = []
    for cf in conf_files:
        d = confdiff.diff_configs(ref_text, Path(cf).read_text(errors="replace"))
        d = confdiff.attribute_changes(d, change_ev)
        d.insert(0, "boitier", boitier_for(cf.name))
        d.insert(1, "fichier", Path(cf).name)
        parts.append(d)
    return pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=cols)


def run(input_dir, config_path, output_dir, ref_conf=None):
    cfg = yaml.safe_load(Path(config_path).read_text())
    errors = validate_config(cfg)
    if errors:
        msg = "Configuration invalide :\n" + "\n".join(f"  - {e}" for e in errors)
        raise SystemExit(msg)
    out = Path(output_dir); out.mkdir(parents=True, exist_ok=True)
    files = ingest.list_log_files(input_dir)
    conf_files = sorted(Path(input_dir).glob("*.conf"))
    if not files and not conf_files:
        raise SystemExit(f"Aucun fichier .log ni .conf dans {input_dir}")

    # Audit des fichiers de configuration FortiGate (.conf) — indépendant des logs.
    def _boitier_for(name):
        for b, pats in (cfg.get("fichiers_boitier") or {}).items():
            if any(p in name for p in pats):
                return b
        return "inconnu"
    config_audit = confaudit.audit_files(conf_files, cfg, boitier_map=_boitier_for)
    # Comparaison à une config de RÉFÉRENCE (optionnelle) : qu'est-ce qui a changé / par qui.
    config_diff = _compute_config_diff(ref_conf, conf_files, input_dir if files else None,
                                       cfg, _boitier_for)

    if not files:
        # Mode AUDIT CONFIG SEUL : import de .conf sans logs.
        empty = pd.DataFrame()
        ref_rows = [{"clé": k, "valeur": str(v)} for k, v in cfg.items()]
        tables = {"unifie": empty, "events": empty, "chains": empty, "agg": empty,
                  "bursts": empty, "diff": empty, "security_rating": empty,
                  "sources_externes": empty, "reputation": empty,
                  "config_audit": config_audit, "config_diff": config_diff,
                  "ref": pd.DataFrame(ref_rows)}
        meta = {"n_files": 0, "n_rows": 0, "dedup": 0,
                "files": [{"name": p.name, "type": "config", "subtype": "fortigate",
                           "reconnu": True, "rows": 0} for p in conf_files],
                "geo_available": False, "reputation_available": False,
                "n_configs": len(conf_files), "n_config_changes": len(config_diff),
                "config_ref": Path(ref_conf).name if ref_conf else None}
        return _emit(out, tables, meta, cfg)

    parts, meta_files = [], []
    for f in files:
        t, s, reconnu = ingest.detect_type(f)
        df = load_file(f, columns=ingest.ANALYSIS_COLS)  # colonnes d'affichage relues en 2ᵉ passe
        df["type"] = df["type"].replace("", t)
        df["subtype"] = df["subtype"].replace("", s)
        meta_files.append({"name": f.name, "type": t, "subtype": s,
                           "reconnu": reconnu, "rows": len(df)})
        parts.append(df)
    full = pd.concat(parts, ignore_index=True)
    del parts  # libère les frames par fichier (évite le doublement transitoire au concat)

    full["timestamp"] = normalize.build_timestamp(full)
    full["boitier"] = normalize.assign_boitier(full, cfg.get("boitiers", {}), cfg.get("fichiers_boitier"))
    full = normalize.deduplicate(full)

    # Optimisation mémoire : colonnes à faible cardinalité -> category (valeurs inchangées)
    for c in ["type", "subtype", "logdesc", "action", "status", "reason",
              "boitier", "source_file", "appcat", "apprisk"]:
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
        # .dt.date calculé une seule fois, puis découpage par jour via groupby
        # (les dates NaT sont écartées automatiquement par le groupby).
        by_day = {d: sub for d, sub in g.groupby(g["timestamp"].dt.date)}
        days = sorted(by_day)
        for a, b in zip(days, days[1:]):
            d = compare.diff_entities(by_day[a], by_day[b], f"{boitier} {a}", f"{boitier} {b}")
            if not d.empty:
                diffs.append(d)
    boits = [b for b in full["boitier"].unique() if b != "inconnu"]
    if len(boits) >= 2:
        d = compare.diff_entities(full[full.boitier == boits[0]],
                                  full[full.boitier == boits[1]], boits[0], boits[1])
        if not d.empty:
            diffs.append(d)
    diff = pd.concat(diffs, ignore_index=True) if diffs else pd.DataFrame()

    # Feuille « Données unifiées » : le frame d'analyse ne porte pas les colonnes
    # d'affichage (msg, ports, octets…). On sélectionne les lignes à afficher (mêmes
    # que l'historique : toutes, ou les MAX dernières par timestamp), puis on RELIT
    # ces seules colonnes pour ces seules lignes (2ᵉ passe -> mémoire bornée).
    MAX_UNIFIE = int(cfg.get("max_lignes_donnees_unifiees", 200000))
    unifie_tronque = len(full) > MAX_UNIFIE
    sel = (full.sort_values("timestamp").tail(MAX_UNIFIE) if unifie_tronque else full).copy()
    wanted = set(zip(sel["source_file"].astype(str), sel["_row"]))
    disp = ingest.load_columns_for_rows(files, wanted, ingest.DISPLAY_ONLY_COLS)
    disp = disp.set_index(["source_file", "_row"]).reindex(
        list(zip(sel["source_file"].astype(str), sel["_row"])))
    for c in ingest.DISPLAY_ONLY_COLS:
        sel[c] = disp[c].fillna("").values
    unifie_cols = TARGET_COLS + ["boitier", "timestamp", "source_file"]
    unifie = sel[unifie_cols]

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
        "config_audit": config_audit,
        "config_diff": config_diff,
        "ref": pd.DataFrame(ref_rows),
    }
    meta = {"n_files": len(files), "n_rows": len(full),
            "dedup": full.attrs.get("dedup_removed", 0), "files": meta_files,
            "geo_available": enricher.available,
            "reputation_available": repdb.available,
            "n_configs": len(conf_files), "n_config_changes": len(config_diff),
            "config_ref": Path(ref_conf).name if ref_conf else None}

    return _emit(out, tables, meta, cfg)


def main():
    ap = argparse.ArgumentParser(description="Analyseur de logs FortiGate")
    ap.add_argument("--input", required=True, help="dossier des fichiers .log")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--output", default="./rapport")
    ap.add_argument("--ref-conf", dest="ref_conf", default=None,
                    help="config .conf de référence/validée à comparer aux .conf du dossier")
    a = ap.parse_args()
    run(a.input, a.config, a.output, ref_conf=a.ref_conf)


if __name__ == "__main__":
    main()
