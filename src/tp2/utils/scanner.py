from pathlib import Path

import yara

REGLES_PERSO = r"""
import "math"

rule Persistance_Cle_Run {
    meta:
        author = "Biglezard"
        description = "persistance via une cle Run du registre (MITRE T1547.001)"
    strings:
        $run = "\\CurrentVersion\\Run" nocase
    condition:
        $run
}

rule Contenu_Packe {
    meta:
        author = "Biglezard"
        description = "contenu packe ou chiffre, entropie tres haute (MITRE T1027.002)"
    condition:
        math.entropy(0, filesize) >= 6.5
}
"""


def charger_regles(dossier: str) -> yara.Rules:
    """
    on compile toutes les règles .yar du dossier --rules, plus nos 2 règles perso,
    et si le dossier existe pas on garde au moins les nôtres
    """
    sources = {"perso": REGLES_PERSO}
    chemin = Path(dossier)
    if chemin.is_dir():
        for fichier in sorted(chemin.iterdir()):
            if fichier.suffix.lower() in (".yar", ".yara"):
                sources[fichier.stem] = fichier.read_text(encoding="utf-8")
    return yara.compile(sources=sources)
