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
from fortilog import confdiff
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

conf_files_up = st.file_uploader(
    "Déposer des fichiers de configuration FortiGate (.conf) — optionnel",
    type=["conf"],
    accept_multiple_files=True,
    help="Backups de configuration FortiGate. Audit de compromission : comptes admin "
         "hors référentiel, admin sans trusted-host, automation sensible, accès exposé.",
)

run_btn = st.button(
    "▶ Lancer l'analyse",
    type="primary",
    disabled=(len(uploaded_files) == 0 and len(conf_files_up) == 0),
)

if run_btn and (uploaded_files or conf_files_up):
    input_dir = Path(tempfile.mkdtemp())
    output_dir = Path(tempfile.mkdtemp())

    try:
        # Écriture des fichiers uploadés dans le dossier temporaire
        for uf in uploaded_files:
            (input_dir / uf.name).write_bytes(uf.getvalue())
        for cf in conf_files_up:
            name = cf.name if cf.name.endswith(".conf") else cf.name + ".conf"
            (input_dir / name).write_bytes(cf.getvalue())

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

        config_audit_df = tables.get("config_audit")
        n_config = 0 if config_audit_df is None else len(config_audit_df)

        col1, col2, col3, col4, col5, col6, col7, col8 = st.columns(8)
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
        col8.metric("🛠 Config", n_config,
                    delta=f"+{n_config}" if n_config else None,
                    delta_color="inverse")

        st.divider()

        # ── Onglets de résultats ──────────────────────────────────────────────
        chains_df = prepare_chains(tables.get("chains"))
        n_chains = len(chains_df)
        tab_report, tab_ev, tab_chains, tab_conf, tab_agg, tab_burst, tab_diff = st.tabs([
            "📝 Rapport",
            "🚨 Événements signalés",
            f"🔗 Chaînes suspectes ({n_chains})",
            f"🛠 Audit config ({n_config})",
            "📊 Tableau de bord",
            "⚡ Rafales",
            "🔄 Différentiels",
        ])

        with tab_report:
            st.markdown(meta.get("analysis", "_Rapport indisponible._"))

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

        with tab_conf:
            if config_audit_df is None or config_audit_df.empty:
                st.info("Aucun fichier de configuration importé, ou aucun constat d'audit.")
            else:
                st.warning(
                    f"⚠️ {n_config} constat(s) d'audit configuration — **SUSPICION à confirmer**, "
                    "pas une preuve de compromission (un admin récent légitime peut être hors référentiel)."
                )
                conf_show = config_audit_df.drop(columns=["sev_rank"], errors="ignore")

                def color_sev_c(val):
                    color = SEV_COLORS.get(val, "")
                    return f"color: {color}; font-weight: bold" if color else ""

                styled_c = conf_show.style.map(color_sev_c, subset=["severite"]) \
                    if "severite" in conf_show.columns else conf_show
                st.dataframe(styled_c, use_container_width=True, height=400)

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


# ── Comparaison de deux configurations ────────────────────────────────────────

st.divider()
st.header("🔁 Comparer deux configurations (.conf)")
st.caption(
    "Comparez une configuration **de référence / validée** à une configuration "
    "**actuelle** : objets ajoutés / supprimés / modifiés (admins, règles, VPN, "
    "interfaces…). Déposez aussi des **logs** ci-dessus pour l'attribution « par qui / quand »."
)

cmp_cols = st.columns(2)
with cmp_cols[0]:
    conf_ref = st.file_uploader("Config de référence (validée)", type=["conf"], key="conf_ref")
with cmp_cols[1]:
    conf_cur = st.file_uploader("Config actuelle (à vérifier)", type=["conf"], key="conf_cur")

cmp_all = st.checkbox("Toutes les sections (sinon : sections sensibles uniquement)", value=False)
cmp_btn = st.button("🔁 Comparer", disabled=(conf_ref is None or conf_cur is None))

if cmp_btn and conf_ref is not None and conf_cur is not None:
    cmp_dir = Path(tempfile.mkdtemp())
    try:
        ref_p = cmp_dir / "ref.conf"; ref_p.write_bytes(conf_ref.getvalue())
        cur_p = cmp_dir / "cur.conf"; cur_p.write_bytes(conf_cur.getvalue())
        # logs pour l'attribution : on réutilise les logs déposés plus haut, s'il y en a
        logs_dir = None
        if uploaded_files:
            logs_dir = cmp_dir / "logs"; logs_dir.mkdir()
            for uf in uploaded_files:
                (logs_dir / uf.name).write_bytes(uf.getvalue())

        diff, cmeta = confdiff.compare(ref_p, cur_p, logs_dir=logs_dir)
        st.markdown(
            f"**Référence** : `{conf_ref.name}` (sauvée par *{cmeta['ok_saved_by'] or '?'}*) — "
            f"**Actuelle** : `{conf_cur.name}` (sauvée par *{cmeta['current_saved_by'] or '?'}*)"
        )
        if diff.empty:
            st.success("Aucun écart sur les sections analysées.")
        else:
            st.warning(
                f"⚠️ {len(diff)} écart(s) — **à confirmer** : un changement légitime n'est pas "
                "une compromission. Attribution issue des logs (vide = hors fenêtre de logs)."
            )
            if not logs_dir:
                st.info("Aucun log déposé : l'attribution « par qui / quand » est indisponible.")

            def color_crit(val):
                color = SEV_COLORS.get(val, "")
                return f"color: {color}; font-weight: bold" if color else ""

            styled = diff.style.map(color_crit, subset=["criticite"]) \
                if "criticite" in diff.columns else diff
            st.dataframe(styled, use_container_width=True, height=480)
            st.download_button(
                "⬇️ Télécharger la comparaison (.csv)",
                data=diff.to_csv(index=False).encode("utf-8"),
                file_name="comparaison_config.csv", mime="text/csv",
            )
    except Exception as e:
        st.error(f"Erreur de comparaison : {e}")
        raise
    finally:
        shutil.rmtree(cmp_dir, ignore_errors=True)
