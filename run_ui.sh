#!/usr/bin/env bash
# Lance l'UI Streamlit de fortilog avec le BON interpréteur Python.
#
# Pourquoi ce script : la machine a deux Python avec chacun un `streamlit`
# (miniforge 3.13, complet et cohérent ; framework 3.11, au pyarrow/numpy bancal).
# Selon le PATH, `streamlit run app.py` peut tomber sur le mauvais et planter
# (ModuleNotFoundError: xlsxwriter, conflit pyarrow/numpy). Ce script force
# l'interpréteur sain et vérifie ses dépendances avant de démarrer.
set -euo pipefail

# Répertoire du projet = dossier de ce script (robuste quel que soit le cwd).
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Interpréteur cible : miniforge par défaut, surchargeable via FORTILOG_PYTHON.
PYTHON="${FORTILOG_PYTHON:-/Users/flab/miniforge3/bin/python}"

if [ ! -x "$PYTHON" ]; then
    echo "❌ Python introuvable : $PYTHON" >&2
    echo "   Définis FORTILOG_PYTHON vers un interpréteur valide." >&2
    exit 1
fi

# Garde-fou : vérifie que les dépendances clés sont importables AVANT de lancer
# l'UI, avec un message d'aide plutôt qu'une stack trace au milieu de Streamlit.
if ! "$PYTHON" -c "import streamlit, xlsxwriter, pandas, pyarrow" 2>/dev/null; then
    echo "❌ Dépendances manquantes dans : $PYTHON" >&2
    echo "   Installe-les avec :" >&2
    echo "     $PYTHON -m pip install -r \"$PROJECT_DIR/requirements-ui.txt\"" >&2
    exit 1
fi

echo "▶ Lancement de l'UI fortilog avec $PYTHON"
exec "$PYTHON" -m streamlit run "$PROJECT_DIR/app.py" "$@"
