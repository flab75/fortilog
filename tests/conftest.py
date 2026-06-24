from __future__ import annotations
import os
import sys
from pathlib import Path
import pytest
import yaml
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CONFIG_PATH = ROOT / "config.yaml"

# Chemins vers de VRAIS exports FortiGate pour les tests @slow. Non versionnés :
# définir via les variables d'environnement FORTILOG_LOGS_T1 / FORTILOG_LOGS_T2.
# Absents -> les tests @slow se skippent proprement (voir require_real_logs).
REAL_LOGS_T1 = Path(os.environ.get("FORTILOG_LOGS_T1", "/path/to/logs/Log_T1"))
REAL_LOGS_T2 = Path(os.environ.get("FORTILOG_LOGS_T2", "/path/to/logs/Log_T2"))


def require_real_logs(path: Path) -> None:
    """Skippe un test @slow si le dossier de vrais logs n'est pas disponible."""
    if not path.exists():
        pytest.skip(f"Vrais logs absents ({path}) — définir FORTILOG_LOGS_T1/T2 pour exécuter.")


@pytest.fixture
def cfg():
    return yaml.safe_load(CONFIG_PATH.read_text())


@pytest.fixture
def fixture_dir():
    return FIXTURES


def load_fixture(name: str) -> pd.DataFrame:
    """Charge une fixture .log en DataFrame via le même pipeline que main.load_file."""
    from fortilog.main import load_file
    return load_file(FIXTURES / name)


def detect_on_fixture(name: str, cfg: dict) -> pd.DataFrame:
    """Charge une fixture, normalise, et lance la détection."""
    from fortilog.main import load_file
    from fortilog import normalize, detect

    df = load_file(FIXTURES / name)
    df["timestamp"] = normalize.build_timestamp(df)
    df["boitier"] = normalize.assign_boitier(df, cfg.get("boitiers", {}), cfg.get("fichiers_boitier"))
    return detect.run_detection(df, cfg)
