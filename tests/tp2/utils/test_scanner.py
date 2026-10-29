from tp2.utils.scanner import charger_regles


def test_charger_regles_prend_le_dossier_et_les_regles_perso(tmp_path):
    """
    test avec un faux dossier --rules : sa règle .yar doit être chargée, le .txt ignoré,
    et nos règles perso doivent toujours être là
    """
    (tmp_path / "test.yar").write_text('rule Regle_Test { strings: $a = "goggins" condition: $a }')
    (tmp_path / "notes.txt").write_text("pas une regle")

    regles = charger_regles(str(tmp_path))
    noms = {match.rule for match in regles.match(data=b"goggins \\CurrentVersion\\Run")}

    assert noms == {"Regle_Test", "Persistance_Cle_Run"}


def test_charger_regles_sans_dossier_garde_les_perso(tmp_path):
    """
    test que si le dossier --rules existe pas, on plante pas et nos règles marchent quand même
    """
    regles = charger_regles(str(tmp_path / "existe_pas"))
    noms = {match.rule for match in regles.match(data=b"\\CurrentVersion\\Run")}

    assert noms == {"Persistance_Cle_Run"}