from tp3.utils import web


class FausseReponse:
    def __init__(self, status_code: int = 200, contenu: bytes = b"", json_data: dict | None = None) -> None:
        self.status_code = status_code
        self.content = contenu
        self._json = json_data or {}

    def json(self) -> dict:
        return self._json


class FausseSession:
    def get(self, url: str) -> FausseReponse:
        return FausseReponse(contenu=b"image-du-captcha")

    def post(self, url: str, data: dict) -> FausseReponse:
        bon = data["captcha"] == "CODE42"
        return FausseReponse(
            status_code=200 if bon else 403,
            json_data={"flag1": "ESGI{web_x}", "host": "1.2.3.4", "port": 9090, "key": "ff00"},
        )


def test_phase_web_recupere_flag1_et_les_infos(monkeypatch):
    """
    test sans réseau : on simule le fuzzing, l'OCR et le serveur, et on vérifie que
    phase_web renvoie bien flag1, host, port et la clé
    """
    monkeypatch.setattr(web, "charger_wordlist", lambda: ["internal-panel"])
    monkeypatch.setattr(web, "trouver_endpoint", lambda cible, mots: "internal-panel")
    monkeypatch.setattr(web, "resoudre_captcha", lambda image: "CODE42")
    monkeypatch.setattr(web.requests, "Session", lambda: FausseSession())

    resultat = web.phase_web("http://cible")

    assert resultat["flag1"] == "ESGI{web_x}"
    assert resultat["host"] == "1.2.3.4"
    assert resultat["port"] == 9090
    assert resultat["key"] == "ff00"
