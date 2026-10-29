import argparse
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.report import generate_report, write_json
from tp2.utils.sample import lister_echantillons
from tp2.utils.scanner import charger_regles
from tp2.utils.triage import analyser_echantillon


def main() -> None:
    """
    point d'entrée du tp2 : lit les options et analyse chaque échantillon du dossier --samples ;
    si un échantillon fait planter l'analyse (fichier abîmé, format inattendu), on le note dans
    le journal et on passe au suivant, pour ne pas perdre les json des autres échantillons
    """
    logger.info("Starting TP2")

    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", required=True, help="dossier des échantillons à analyser")
    parser.add_argument("--rules", required=True, help="dossier des règles yara")
    parser.add_argument("--out", required=True, help="dossier où écrire un json par échantillon")
    parser.add_argument("--pdf", default="rapport_triage.pdf", help="chemin du rapport pdf")
    args = parser.parse_args()

    Path(args.out).mkdir(parents=True, exist_ok=True)
    regles = charger_regles(args.rules)
    resultats = []
    for chemin in lister_echantillons(args.samples):
        logger.info(f"Analyse de {chemin.name}")
        try:
            resultat = analyser_echantillon(chemin, regles)
        except Exception as erreur:
            logger.error(f"Échec de l'analyse de {chemin.name} : {erreur}")
            continue
        write_json(resultat, args.out, chemin.name)
        resultats.append(resultat)

    if resultats:
        generate_report(resultats, args.pdf)


if __name__ == "__main__":
    main()
