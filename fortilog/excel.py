"""Génération du classeur .xlsx (xlsxwriter). Sortie autonome lisible par Excel (Mac/Win)."""
from __future__ import annotations
import pandas as pd

SHEETS_ORDER = ["Tableau de bord", "Evenements signales", "Chaines suspectes",
                "IP malveillantes", "Sources externes", "Rafales", "Differentiels",
                "Donnees unifiees", "Referentiel"]

SEV_COLORS = {"critique": "#C00000", "eleve": "#E26B0A", "moyen": "#BF8F00",
              "faible": "#7F7F7F", "info": "#9CC3E5"}


def _write_df(writer, name, df, header_fmt, max_width=60):
    if df is None or df.empty:
        df = pd.DataFrame({"(vide)": ["aucune donnée"]})
    df = df.copy()
    for c in df.columns:
        if pd.api.types.is_datetime64_any_dtype(df[c]):
            df[c] = df[c].dt.strftime("%Y-%m-%d %H:%M:%S")
    df = df.fillna("")
    df.to_excel(writer, sheet_name=name[:31], index=False, startrow=1, header=False)
    ws = writer.sheets[name[:31]]
    for j, col in enumerate(df.columns):
        ws.write(0, j, str(col), header_fmt)
        col_len = int(df[col].astype(str).str.len().max()) if len(df) else 10
        width = min(max_width, max(10, col_len, len(str(col)) + 2))
        ws.set_column(j, j, width)
    ws.freeze_panes(1, 0)
    if len(df):
        ws.autofilter(0, 0, len(df), len(df.columns) - 1)
    return ws


def write_workbook(path, tables, cfg):
    with pd.ExcelWriter(path, engine="xlsxwriter") as writer:
        wb = writer.book
        header_fmt = wb.add_format({"bold": True, "bg_color": "#1F4E78",
                                    "font_color": "white", "border": 1})
        # Données unifiées
        _write_df(writer, "Donnees unifiees", tables["unifie"], header_fmt)
        # Événements signalés (avec couleur par sévérité)
        ev = tables["events"]
        ws = _write_df(writer, "Evenements signales", ev, header_fmt)
        if ev is not None and not ev.empty and "severite" in ev.columns:
            col = list(ev.columns).index("severite")
            for sev, color in SEV_COLORS.items():
                ws.conditional_format(1, col, len(ev), col, {
                    "type": "text", "criteria": "containing", "value": sev,
                    "format": wb.add_format({"bg_color": color, "font_color": "white"})})
        # Chaînes suspectes (corrélation temporelle) — marquées « à confirmer »
        _write_df(writer, "Chaines suspectes", tables.get("chains"), header_fmt)
        # IP malveillantes connues (threat intel) — sources en liste de réputation
        _write_df(writer, "IP malveillantes", tables.get("reputation"), header_fmt)
        # Sources externes (contexte géo/ASN) — top des IP externes par volume
        _write_df(writer, "Sources externes", tables.get("sources_externes"), header_fmt)
        _write_df(writer, "Tableau de bord", tables["agg"], header_fmt)
        _write_df(writer, "Rafales", tables["bursts"], header_fmt)
        _write_df(writer, "Differentiels", tables["diff"], header_fmt)
        _write_df(writer, "Referentiel", tables["ref"], header_fmt)
