from tp2.utils.scanner import charger_regles, yara_scan


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


def test_yara_scan_renvoie_les_noms_tries(tmp_path):
    """
    test avec des octets bien mélangés (entropie max) plus une clé Run : nos 2 règles
    doivent sonner, et les noms doivent sortir triés
    """
    regles = charger_regles(str(tmp_path))
    data = bytes(range(256)) * 4 + b"\\CurrentVersion\\Run"

    assert yara_scan(data, regles) == ["Contenu_Packe", "Persistance_Cle_Run"]


def test_yara_scan_fichier_sain(tmp_path):
    """
    test qu'un fichier banal ne déclenche aucune règle, sinon nos règles seraient trop larges
    """
    regles = charger_regles(str(tmp_path))

    assert yara_scan(b"juste un fichier banal", regles) == []
