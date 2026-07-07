# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests pour suivi.py + ack.py : état persistant, statuts, acquittement, dégradation."""
import json
import shutil
import tempfile
from pathlib import Path

import pandas as pd
import pytest

from fortilog import ack, suivi
from tests.conftest import CONFIG_PATH, FIXTURES

# R14 (pays) se rebranche sur l'historique compte×pays persistant (P5.2) : un même
# compte×pays vu au run 1 n'est plus « nouveau » au run 2 -> le nombre d'événements
# n'est PAS stable d'un run à l'autre pour cette règle précise (comportement voulu).
_REGLES_PAYS_NOUVEAUTE = {
    "Connexion admin depuis un pays non vu plus tôt dans cette analyse (SUSPICION comportementale)",
    "Connexion admin depuis un pays jamais vu pour ce compte, historique inclus "
    "(SUSPICION comportementale)",
}


def _run_twice_dirs():
    input_dir = Path(tempfile.mkdtemp())
    output_dir = Path(tempfile.mkdtemp())
    shutil.copy(FIXTURES / "compromission_scenario.log", input_dir / "scenario.log")
    return input_dir, output_dir


def test_run1_nouveau_run2_connu():
    """Run 1 : tous les constats `nouveau` ; run 2 mêmes fixtures : tous `connu`."""
    from fortilog.main import run
    input_dir, output_dir = _run_twice_dirs()
    try:
        tables1, meta1 = run(str(input_dir), str(CONFIG_PATH), str(output_dir))
        assert (tables1["events"]["suivi"] == "nouveau").all()
        assert meta1["suivi"]["n_nouveaux"] == meta1["suivi"]["n_constats"] > 0
        assert not meta1["suivi"]["anterieur"]
        # pas de mention « depuis l'analyse du » sans état antérieur
        assert "depuis l'analyse du" not in meta1["analysis"]

        etat = json.loads((output_dir / "etat_suivi.json").read_text(encoding="utf-8"))
        assert etat["version"] == 1
        assert len(etat["analyses"]) == 1
        assert all(c["statut"] == "nouveau" for c in etat["constats"].values())

        tables2, meta2 = run(str(input_dir), str(CONFIG_PATH), str(output_dir))
        assert (tables2["events"]["suivi"] == "connu").all()
        assert meta2["suivi"]["n_nouveaux"] == 0
        assert "NOUVEAU(X) depuis l'analyse du" in meta2["analysis"]
        etat2 = json.loads((output_dir / "etat_suivi.json").read_text(encoding="utf-8"))
        assert len(etat2["analyses"]) == 2
    finally:
        shutil.rmtree(input_dir, ignore_errors=True)
        shutil.rmtree(output_dir, ignore_errors=True)


def test_ack_tag_et_exclusion_du_decompte(capsys):
    """Acquitter un id : tag [ACQUITTÉ …] présent au run suivant + exclu du décompte."""
    from fortilog.main import run
    input_dir, output_dir = _run_twice_dirs()
    try:
        tables1, meta1 = run(str(input_dir), str(CONFIG_PATH), str(output_dir))
        etat_path = output_dir / "etat_suivi.json"
        cid = tables1["events"]["constat_id"].iloc[0]

        rc = ack.main([cid, "--etat", str(etat_path), "--motif", "faux positif de test"])
        assert rc == 0
        etat = json.loads(etat_path.read_text(encoding="utf-8"))
        assert etat["constats"][cid]["statut"] == "acquitte"
        assert etat["constats"][cid]["motif"] == "faux positif de test"

        tables2, meta2 = run(str(input_dir), str(CONFIG_PATH), str(output_dir))
        ev = tables2["events"]
        acq = ev[ev["constat_id"] == cid]
        assert (acq["suivi"] == "acquitte").all()
        assert acq["detail"].str.contains(r"\[ACQUITTÉ le \d{2}/\d{2}/\d{4}\]").all()
        # exclu du décompte, jamais supprimé
        assert meta2["suivi"]["n_acquittes"] >= 1
        assert "acquitté(s) hors décompte" in meta2["analysis"]
        # hors règle de nouveauté "pays" (R14) : elle se rebranche sur l'historique
        # persistant entre run1 et run2, donc son nombre d'occurrences n'est PAS stable.
        stable = lambda df: df[~df["regle"].isin(_REGLES_PAYS_NOUVEAUTE)]
        assert len(stable(ev)) == len(stable(tables1["events"]))
    finally:
        shutil.rmtree(input_dir, ignore_errors=True)
        shutil.rmtree(output_dir, ignore_errors=True)


def test_etat_corrompu_warning_et_fichier_intact():
    """État corrompu : warning explicite, run normal SANS suivi, fichier laissé intact."""
    from fortilog.main import run
    input_dir, output_dir = _run_twice_dirs()
    try:
        etat_path = output_dir / "etat_suivi.json"
        etat_path.write_text("{ceci n'est pas du json", encoding="utf-8")
        tables, meta = run(str(input_dir), str(CONFIG_PATH), str(output_dir))
        assert meta["suivi"]["disponible"] is False
        assert "illisible" in meta["suivi"]["warning"]
        assert "Suivi entre analyses indisponible" in meta["analysis"]
        assert "suivi" not in tables["events"].columns
        # jamais écrasé silencieusement
        assert etat_path.read_text(encoding="utf-8") == "{ceci n'est pas du json"
    finally:
        shutil.rmtree(input_dir, ignore_errors=True)
        shutil.rmtree(output_dir, ignore_errors=True)


def test_stabilite_constat_id():
    """Même entrée = même id ; timestamp différent = même id ; acteur différent = autre id."""
    ev = pd.DataFrame({
        "timestamp": pd.to_datetime(["2026-06-23 10:00"]),
        "regle": ["Brute-force sur COMPTE VALIDE (passwd_invalid)"],
        "boitier": ["T1"], "user": ["adminA"], "srcip": ["198.51.100.9"],
    })
    id1 = suivi.ids_evenements(ev).iloc[0]
    ev2 = ev.copy()
    ev2["timestamp"] = pd.to_datetime(["2026-06-25 03:00"])  # 2 jours plus tard
    assert suivi.ids_evenements(ev2).iloc[0] == id1
    ev3 = ev.copy()
    ev3["srcip"] = ["203.0.113.9"]
    assert suivi.ids_evenements(ev3).iloc[0] != id1
    assert len(id1) == 16


def test_ack_liste_et_id_inconnu(tmp_path, capsys):
    etat_path = tmp_path / "etat_suivi.json"
    etat_path.write_text(json.dumps({
        "version": 1, "analyses": [{"date": "2026-07-07", "n_constats": 1}],
        "constats": {"abcd1234abcd1234": {
            "premiere_vue": "2026-07-07", "derniere_vue": "2026-07-07",
            "statut": "nouveau", "regle": "R-test", "resume": "user=x"}}},
        ensure_ascii=False), encoding="utf-8")
    assert ack.main(["--etat", str(etat_path), "--list"]) == 0
    out = capsys.readouterr().out
    assert "abcd1234abcd1234" in out and "R-test" in out
    with pytest.raises(SystemExit):
        ack.main(["id_inexistant", "--etat", str(etat_path)])


def test_comptes_vus_persiste_entre_runs():
    """R14 (pays) branché sur l'état persistant : un couple compte×pays déjà vu au
    run 1 n'est plus signalé « nouveau » au run 2, mais un pays réellement inédit
    pour ce compte l'est toujours (libellé « historique inclus »)."""
    from fortilog.main import run
    input_dir, output_dir = _run_twice_dirs()
    try:
        shutil.copy(FIXTURES / "comportement_pays_run1.log", input_dir / "scenario.log")
        tables1, _ = run(str(input_dir), str(CONFIG_PATH), str(output_dir))
        pays1 = tables1["events"][tables1["events"]["regle"].str.contains("un pays", na=False)]
        assert len(pays1) == 1
        assert "user=adminZ" in pays1["detail"].iloc[0]

        etat = json.loads((output_dir / "etat_suivi.json").read_text(encoding="utf-8"))
        assert "US" in etat["comptes_vus"]["adminZ"]

        (input_dir / "scenario.log").unlink()
        shutil.copy(FIXTURES / "comportement_pays_run2.log", input_dir / "scenario.log")
        tables2, _ = run(str(input_dir), str(CONFIG_PATH), str(output_dir))
        pays2 = tables2["events"][tables2["events"]["regle"].str.contains("un pays", na=False)]
        # le retour en US (déjà vu) n'est plus signalé ; seul AU (inédit pour adminZ) l'est
        assert len(pays2) == 1
        assert "pays=AU" in pays2["detail"].iloc[0]
        assert "historique inclus" in pays2["regle"].iloc[0]
    finally:
        shutil.rmtree(input_dir, ignore_errors=True)
        shutil.rmtree(output_dir, ignore_errors=True)
