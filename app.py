"""UI Streamlit pour fortilog — analyse de logs FortiGate.

Lancement : streamlit run app.py
Toute la logique d'analyse reste dans fortilog.main.run().
"""
import sys
import tempfile
import shutil
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from fortilog.main import run
from fortilog.ui_helpers import (
    prepare_events, prepare_metrics, prepare_agg,
    prepare_bursts, prepare_diff, prepare_chains, SEV_COLORS,
)

DEFAULT_CONFIG = ROOT / "config.yaml"

st.set_page_config(
    page_title="FortiLog — Analyseur de logs FortiGate",
    page_icon="🔒",
    layout="wide",
)


# ── Sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("⚙️ Configuration")
    config_file = st.file_uploader(
        "Référentiel config.yaml (optionnel)",
        type=["yaml", "yml"],
        help="Laissez vide pour utiliser le config.yaml du projet.",
    )
    st.caption(
        "Si aucun fichier n'est fourni, le `config.yaml` du répertoire du projet "
        "est utilisé."
    )
    st.divider()
    st.markdown(
        "**Principe :** l'outil **signale et structure** ; "
        "le **verdict reste humain**. Aucune conclusion de compromission "
        "n'est émise sans preuve dans les logs."
    )


# ── Zone principale ───────────────────────────────────────────────────────────

st.title("🔒 FortiLog — Analyseur de logs FortiGate")
st.caption(
    "Importez vos exports de logs FortiCloud/FortiGate, lancez l'analyse et "
    "téléchargez le rapport Excel."
)

uploaded_files = st.file_uploader(
    "Déposer les fichiers de logs (.log ou .txt)",
    type=["log", "txt"],
    accept_multiple_files=True,
    help="Exports FortiGate au format clé=\"valeur\". Un ou plusieurs fichiers.",
)

run_btn = st.button(
    "▶ Lancer l'analyse",
    type="primary",
    disabled=len(uploaded_files) == 0,
)

if run_btn and uploaded_files:
    input_dir = Path(tempfile.mkdtemp())
    output_dir = Path(tempfile.mkdtemp())

    try:
        # Écriture des fichiers uploadés dans le dossier temporaire
        for uf in uploaded_files:
            (input_dir / uf.name).write_bytes(uf.getvalue())

        # Résolution du config
        if config_file is not None:
            cfg_path = input_dir / "_config.yaml"
            cfg_path.write_bytes(config_file.getvalue())
        else:
            cfg_path = DEFAULT_CONFIG

        with st.spinner("Analyse en cours…"):
            tables, meta = run(str(input_dir), str(cfg_path), str(output_dir))

        # ── Métriques ────────────────────────────────────────────────────────
        m = prepare_metrics(meta, tables["events"], tables["agg"],
                            tables["bursts"], tables.get("chains"))

        st.success(f"Analyse terminée — {m['n_rows']:,} événements ({m['n_dedup']:,} doublons retirés)")

        col1, col2, col3, col4, col5, col6, col7 = st.columns(7)
        col1.metric("Fichiers", m["n_files"])
        col2.metric("Événements", f"{m['n_rows']:,}")
        col3.metric("Signalés", m["n_events"])

        crit_delta = f"+{m['critique']}" if m["critique"] else "0"
        col4.metric("🔴 Critiques", m["critique"],
                    delta=crit_delta if m["critique"] else None,
                    delta_color="inverse")
        col5.metric("🟠 Élevés", m["eleve"])
        col6.metric("🔗 Chaînes", m["n_chains"],
                    delta=f"+{m['n_chains']}" if m["n_chains"] else None,
                    delta_color="inverse")
        col7.metric("⚡ Rafales", m["n_bursts"])

        st.divider()

        # ── Onglets de résultats ──────────────────────────────────────────────
        chains_df = prepare_chains(tables.get("chains"))
        n_chains = len(chains_df)
        tab_ev, tab_chains, tab_agg, tab_burst, tab_diff = st.tabs([
            "🚨 Événements signalés",
            f"🔗 Chaînes suspectes ({n_chains})",
            "📊 Tableau de bord",
            "⚡ Rafales",
            "🔄 Différentiels",
        ])

        with tab_ev:
            ev_df = prepare_events(tables["events"])
            if ev_df.empty:
                st.info("Aucun événement signalé.")
            else:
                st.caption(f"{len(ev_df)} événement(s) — triés par sévérité décroissante")
                # Coloration par sévérité
                def color_sev(val):
                    color = SEV_COLORS.get(val, "")
                    return f"color: {color}; font-weight: bold" if color else ""

                styled = ev_df.style.map(color_sev, subset=["severite"]) \
                    if "severite" in ev_df.columns else ev_df
                st.dataframe(styled, use_container_width=True, height=500)

        with tab_chains:
            if chains_df.empty:
                st.info("Aucune chaîne suspecte (séquence accès → compte → exfiltration) détectée.")
            else:
                st.warning(
                    f"⚠️ {n_chains} chaîne(s) suspecte(s) — **corrélation temporelle à CONFIRMER**, "
                    "pas une preuve de compromission."
                )
                st.dataframe(chains_df, use_container_width=True)

        with tab_agg:
            agg_df = prepare_agg(tables["agg"])
            if agg_df.empty:
                st.info("Aucun agrégat disponible.")
            else:
                st.caption("Agrégats par boîtier / jour")
                st.dataframe(agg_df, use_container_width=True)

        with tab_burst:
            burst_df = prepare_bursts(tables["bursts"])
            if burst_df.empty:
                st.info("Aucune rafale détectée.")
            else:
                st.caption(f"{len(burst_df)} rafale(s) détectée(s)")
                st.dataframe(burst_df, use_container_width=True)

        with tab_diff:
            diff_df = prepare_diff(tables["diff"])
            if diff_df.empty:
                st.info("Aucun différentiel (un seul fichier ou une seule date).")
            else:
                alerts = diff_df[diff_df.get("alerte", False) == True] \
                    if "alerte" in diff_df.columns else diff_df.iloc[0:0]
                if not alerts.empty:
                    st.warning(f"⚠️ {len(alerts)} entité(s) de priorité 1 apparue(s)")
                st.dataframe(diff_df, use_container_width=True)

        # ── Téléchargement ───────────────────────────────────────────────────
        st.divider()
        xlsx_path = output_dir / "rapport_fortigate.xlsx"
        if xlsx_path.exists():
            st.download_button(
                label="⬇️ Télécharger le rapport Excel (.xlsx)",
                data=xlsx_path.read_bytes(),
                file_name="rapport_fortigate.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                type="primary",
            )

    except SystemExit as e:
        st.error(str(e))
    except Exception as e:
        st.error(f"Erreur inattendue : {e}")
        raise
    finally:
        shutil.rmtree(input_dir, ignore_errors=True)
        # output_dir conservé le temps du téléchargement (durée de la session)
