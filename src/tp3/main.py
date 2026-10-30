import argparse

from tp3.utils.config import logger
from tp3.utils.reseau import phase_reseau
from tp3.utils.web import phase_web


def main() -> None:
    """
    lance l'exploit : la phase web donne flag1 et les infos du service TCP,
    puis la phase réseau donne le flag final ; on affiche les deux drapeaux
    """
    parser = argparse.ArgumentParser(description="Exploit TP3 : récupère flag1 puis le flag final")
    parser.add_argument("--target", required=True, help="URL de la cible, ex. http://localhost:8080")
    args = parser.parse_args()

    logger.info(f"Cible : {args.target}")
    infos = phase_web(args.target)
    print(f"[+] FLAG1: {infos['flag1']}")

    final = phase_reseau(infos["host"], infos["port"], infos["key"])
    print(f"[+] FLAG_FINAL: {final}")


if __name__ == "__main__":
    main()
