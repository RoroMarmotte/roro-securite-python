import argparse
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.sample import lister_echantillons


def main() -> None:
    """
    point d'entrée du tp2 : lit les options et analyse chaque échantillon du dossier --samples
    """
    logger.info("Starting TP2")

    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", required=True, help="dossier des échantillons à analyser")
    parser.add_argument("--rules", required=True, help="dossier des règles yara")
    parser.add_argument("--out", required=True, help="dossier où écrire un json par échantillon")
    args = parser.parse_args()

    Path(args.out).mkdir(parents=True, exist_ok=True)
    for chemin in lister_echantillons(args.samples):
        logger.info(f"Analyse de {chemin.name}")


if __name__ == "__main__":
    main()