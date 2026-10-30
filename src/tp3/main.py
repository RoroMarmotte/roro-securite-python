import argparse

from tp3.utils.config import logger


def main() -> None:
    """
    point d'entrée de l'exploit : on prend --target, on fera la phase web (flag1) puis la
    phase réseau (flag final), et on affiche les deux drapeaux sur la sortie
    """
    parser = argparse.ArgumentParser(description="Exploit TP3 : récupère flag1 puis le flag final")
    parser.add_argument("--target", required=True, help="URL de la cible, ex. http://localhost:8080")
    args = parser.parse_args()

    logger.info(f"Cible : {args.target}")
    # phase web   -> flag1, host, port, clé   (étapes 2 à 4)
    # phase réseau -> flag final               (étape 5)


if __name__ == "__main__":
    main()
