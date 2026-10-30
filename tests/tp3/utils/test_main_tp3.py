import pytest

from tp3 import main as module_main
from tp3.main import main


def test_main_exige_target(monkeypatch):
    """
    test que sans --target l'outil s'arrête proprement (argparse lève SystemExit)
    """
    monkeypatch.setattr("sys.argv", ["tp3"])

    with pytest.raises(SystemExit):
        main()


def test_main_affiche_les_deux_flags(monkeypatch, capsys):
    """
    test qu'avec --target, main enchaîne les deux phases (simulées) et affiche les
    deux drapeaux sur la sortie, au bon format
    """
    monkeypatch.setattr("sys.argv", ["tp3", "--target", "http://cible"])
    monkeypatch.setattr(
        module_main, "phase_web", lambda target: {"flag1": "ESGI{web_x}", "host": "h", "port": 1, "key": "ff"}
    )
    monkeypatch.setattr(module_main, "phase_reseau", lambda host, port, cle: "ESGI{chain_x}")

    main()

    sortie = capsys.readouterr().out
    assert "[+] FLAG1: ESGI{web_x}" in sortie
    assert "[+] FLAG_FINAL: ESGI{chain_x}" in sortie
