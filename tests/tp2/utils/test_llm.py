import requests
from types import SimpleNamespace
from tp2.utils.llm import appeler_llm
from tp2.utils.llm import DEBUT_DONNEES, FIN_DONNEES, construire_resume


def test_construire_resume_limite_donnee():
    """
    Test qu'on se trouve entre les balise déclaré en constante et qu'on retrouve bien l'enprumpte
    """
    metadata = {"sha256": "abc", "size": 10, "entropy": 4.8}
    iocs = {"domains": ["c2.example.test"], "ips": [], "urls": [], "mutex": [], "registry": []}

    resume = construire_resume(metadata, iocs, ["connect"], ["Has_Mutex"])

    debut = resume.find(DEBUT_DONNEES)
    fin = resume.find(FIN_DONNEES)
    position_domaine = resume.find("c2.example.test")
    assert debut < position_domaine < fin
    assert "sha256 : abc" in resume


def test_appeler_llm_renvoie_reponse(monkeypatch):
    """
    Un faux appel de llm pour voir si on a le bon format de réponse dans dictionnaire
    """

    def faux_post(*args, **kwargs):
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"choices": [{"message": {"content": "fonctionnel"}}]},
        )

    monkeypatch.setenv("OPENROUTER_API_KEY", "fausse-cle")
    monkeypatch.setattr("tp2.utils.llm.requests.post", faux_post)

    resultat = appeler_llm("test")

    assert resultat == "fonctionnel"


def test_appeler_llm_sans_reseau(monkeypatch):
    """
    Vérifie qu'on renvoie None en cas de coupure de réseaux ou autre problème avec le trafic avec openrouteur
    """

    def faux_post(*args, **kwargs):
        raise requests.ConnectionError()

    monkeypatch.setenv("OPENROUTER_API_KEY", "fausse-cle")
    monkeypatch.setattr("tp2.utils.llm.requests.post", faux_post)

    assert appeler_llm("test") is None
