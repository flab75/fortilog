"""Tests de l'interface CLI (main.main()) : code retour, --json/--csv, --quiet.
La logique d'analyse elle-même est déjà couverte par test_detect.py/test_integration.py ;
ici on vérifie uniquement la couche CLI ajoutée par-dessus run()."""
import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from fortilog.main import main, _exit_code
from tests.conftest import CONFIG_PATH, FIXTURES


def _run_cli(argv, input_dir, output_dir):
    old_argv = sys.argv
    sys.argv = ["fortilog", "--input", str(input_dir), "--config", str(CONFIG_PATH),
                "--output", str(output_dir)] + argv
    try:
        with pytest.raises(SystemExit) as exc:
            main()
        return exc.value.code
    finally:
        sys.argv = old_argv


def _dirs():
    return Path(tempfile.mkdtemp()), Path(tempfile.mkdtemp())


def test_exit_code_zero_sur_logs_benins():
    input_dir, output_dir = _dirs()
    try:
        shutil.copy(FIXTURES / "benign_mix.log", input_dir / "scenario.log")
        code = _run_cli([], input_dir, output_dir)
        assert code == 0
    finally:
        shutil.rmtree(input_dir, ignore_errors=True)
        shutil.rmtree(output_dir, ignore_errors=True)


def test_exit_code_deux_sur_scenario_compromission():
    """Le scénario de compromission remonte au moins un critique -> code 2."""
    input_dir, output_dir = _dirs()
    try:
        shutil.copy(FIXTURES / "compromission_scenario.log", input_dir / "scenario.log")
        code = _run_cli([], input_dir, output_dir)
        assert code == 2
    finally:
        shutil.rmtree(input_dir, ignore_errors=True)
        shutil.rmtree(output_dir, ignore_errors=True)


def test_exit_code_depuis_tables_directement():
    """_exit_code isolée des cas limites : pas de colonne severite / DataFrame vide."""
    import pandas as pd
    assert _exit_code({"events": pd.DataFrame()}) == 0
    assert _exit_code({"events": pd.DataFrame({"severite": ["info", "faible"]})}) == 0
    assert _exit_code({"events": pd.DataFrame({"severite": ["eleve"]})}) == 1
    assert _exit_code({"events": pd.DataFrame({"severite": ["eleve", "critique"]})}) == 2


def test_json_dir_ecrit_les_tables():
    input_dir, output_dir = _dirs()
    json_dir = Path(tempfile.mkdtemp())
    try:
        shutil.copy(FIXTURES / "benign_mix.log", input_dir / "scenario.log")
        _run_cli(["--json", str(json_dir)], input_dir, output_dir)
        events_json = json_dir / "events.json"
        assert events_json.is_file()
        rows = json.loads(events_json.read_text(encoding="utf-8"))
        assert isinstance(rows, list)
        # les sorties habituelles (classeur, rapport texte) restent produites
        assert (output_dir / "rapport_fortigate.xlsx").is_file()
    finally:
        shutil.rmtree(input_dir, ignore_errors=True)
        shutil.rmtree(output_dir, ignore_errors=True)
        shutil.rmtree(json_dir, ignore_errors=True)


def test_csv_dir_ecrit_les_tables():
    input_dir, output_dir = _dirs()
    csv_dir = Path(tempfile.mkdtemp())
    try:
        shutil.copy(FIXTURES / "benign_mix.log", input_dir / "scenario.log")
        _run_cli(["--csv", str(csv_dir)], input_dir, output_dir)
        events_csv = csv_dir / "events.csv"
        assert events_csv.is_file()
        assert "regle" in events_csv.read_text(encoding="utf-8").splitlines()[0]
    finally:
        shutil.rmtree(input_dir, ignore_errors=True)
        shutil.rmtree(output_dir, ignore_errors=True)
        shutil.rmtree(csv_dir, ignore_errors=True)


def test_quiet_supprime_stdout_stderr_mais_garde_les_fichiers(capsys):
    input_dir, output_dir = _dirs()
    try:
        shutil.copy(FIXTURES / "benign_mix.log", input_dir / "scenario.log")
        _run_cli(["--quiet"], input_dir, output_dir)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""
        assert (output_dir / "rapport_fortigate.xlsx").is_file()
        assert (output_dir / "rapport_fortigate.txt").is_file()
    finally:
        shutil.rmtree(input_dir, ignore_errors=True)
        shutil.rmtree(output_dir, ignore_errors=True)


def test_sans_quiet_progression_ingestion_sur_stderr(capsys):
    input_dir, output_dir = _dirs()
    try:
        shutil.copy(FIXTURES / "benign_mix.log", input_dir / "scenario.log")
        _run_cli([], input_dir, output_dir)
        captured = capsys.readouterr()
        assert "fichier 1/1 : scenario.log" in captured.err
        assert captured.out != ""
    finally:
        shutil.rmtree(input_dir, ignore_errors=True)
        shutil.rmtree(output_dir, ignore_errors=True)
