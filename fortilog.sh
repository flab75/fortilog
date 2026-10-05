#!/usr/bin/env bash
# fortilog — lanceur PORTABLE : fonctionne là où le dossier est posé, quel que soit le
# dossier courant et sans chemin propre à une machine.
#
#   ./fortilog.sh                  UI Streamlit (défaut ; options passées à streamlit)
#   ./fortilog.sh analyse ARGS...  CLI d'analyse (= python -m fortilog.main ARGS)
#   ./fortilog.sh maj-bases [--force]   met à jour les bases géo/ASN/réputation/Fortinet
#   ./fortilog.sh installer        (ré)installe l'environnement .venv du projet
#   ./fortilog.sh tests [ARGS]     suite pytest rapide
#
# Au premier lancement, un environnement isolé `.venv/` est créé DANS le dossier du projet
# avec un Python >= 3.11 trouvé sur la machine (FORTILOG_PYTHON pour en imposer un), puis
# les dépendances sont installées (réseau requis une fois). Ensuite, plus rien d'externe.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
VENV="$PROJECT_DIR/.venv"
VPY="$VENV/bin/python"

die() { echo "❌ $*" >&2; exit 1; }
info() { echo "▶ $*" >&2; }

version_ok() {   # $1 = interpréteur ; vrai si Python >= 3.11
    "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null
}

trouver_python() {
    if [ -n "${FORTILOG_PYTHON:-}" ]; then
        version_ok "$FORTILOG_PYTHON" || die "FORTILOG_PYTHON=$FORTILOG_PYTHON n'est pas un Python >= 3.11"
        echo "$FORTILOG_PYTHON"; return
    fi
    for c in python3.13 python3.12 python3.11 python3; do
        if command -v "$c" >/dev/null 2>&1 && version_ok "$(command -v "$c")"; then
            command -v "$c"; return
        fi
    done
    die "aucun Python >= 3.11 trouvé (installez-le, ou définissez FORTILOG_PYTHON)"
}

installer() {
    local py; py="$(trouver_python)"
    info "Création de l'environnement $VENV avec $py ($("$py" -V 2>&1))"
    rm -rf "$VENV"
    "$py" -m venv "$VENV" || die "création du venv impossible"
    "$VPY" -m pip install -q --upgrade pip
    "$VPY" -m pip install -q -r "$PROJECT_DIR/requirements-ui.txt" -r "$PROJECT_DIR/requirements-dev.txt" \
        || die "installation des dépendances échouée (réseau ?) — relancez : $0 installer"
    info "Environnement prêt."
}

# Venv absent, cassé (dossier déplacé : les venv contiennent des chemins absolus) ou
# incomplet -> réinstallation automatique.
assurer_env() {
    if [ ! -x "$VPY" ] || ! "$VPY" -c 'import streamlit, pandas, xlsxwriter, yaml, openpyxl' 2>/dev/null; then
        [ -d "$VENV" ] && info "Environnement $VENV absent, déplacé ou incomplet : réinstallation."
        installer
    fi
}

cmd="${1:-ui}"
[ $# -gt 0 ] && shift

case "$cmd" in
    installer)
        installer ;;
    analyse|cli)
        assurer_env
        # Pas de cd : les chemins --input/--output restent relatifs au dossier de l'utilisateur.
        PYTHONPATH="$PROJECT_DIR${PYTHONPATH:+:$PYTHONPATH}" exec "$VPY" -m fortilog.main "$@" ;;
    maj-bases)
        assurer_env
        PYTHONPATH="$PROJECT_DIR${PYTHONPATH:+:$PYTHONPATH}" exec "$VPY" -m fortilog.maj_bases "$@" ;;
    tests)
        assurer_env
        cd "$PROJECT_DIR"
        exec "$VPY" -m pytest -m "not slow" -q "$@" ;;
    -h|--help|aide)
        sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//' ;;
    ui|-*)
        [ "$cmd" != ui ] && set -- "$cmd" "$@"   # options streamlit directement (ex. --server.port 8600)
        assurer_env
        cd "$PROJECT_DIR"
        info "Lancement de l'UI fortilog ($PROJECT_DIR) — Ctrl+C pour arrêter"
        exec "$VPY" -m streamlit run "$PROJECT_DIR/app.py" "$@" ;;
    *)
        die "commande inconnue : $cmd (voir $0 --help)" ;;
esac
