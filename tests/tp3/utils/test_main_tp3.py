import pytest

from tp3.main import main


def test_main_exige_target(monkeypatch):
    """
    test que sans --target l'outil s'arrête proprement (argparse lève SystemExit),
    au lieu de partir sur une cible inconnue
    """
    monkeypatch.setattr("sys.argv", ["tp3"])

    with pytest.raises(SystemExit):
        main()


def test_main_accepte_target(monkeypatch):
    """
    test qu'avec --target le main lit bien l'option et ne plante pas
    """
    monkeypatch.setattr("sys.argv", ["tp3", "--target", "http://localhost:8080"])

    main()
