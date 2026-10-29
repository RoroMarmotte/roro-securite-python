import json

import requests

from tp2.utils.llm import (
    DEBUT_DONNEES,
    FIN_DONNEES,
    appeler_llm,
    construire_resume,
    llm_triage,
    valider_verdict,
)


class FausseReponse:
    """
    imite la réponse d'openrouter : pas d'erreur http, et un json qui contient le texte du llm
    """

    def raise_for_status(self):
        pass

    def json(self):
        return {"choices": [{"message": {"content": "fonctionnel"}}]}


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

    def faux_post(url, headers, json, timeout):
        return FausseReponse()

    monkeypatch.setenv("OPENROUTER_API_KEY", "fausse-cle")
    monkeypatch.setattr("tp2.utils.llm.requests.post", faux_post)

    resultat = appeler_llm("test")

    assert resultat == "fonctionnel"


def test_appeler_llm_sans_reseau(monkeypatch):
    """
    Vérifie qu'on renvoie None en cas de coupure de réseaux ou autre problème avec le trafic avec openrouteur
    """

    def faux_post(url, headers, json, timeout):
        raise requests.ConnectionError()

    monkeypatch.setenv("OPENROUTER_API_KEY", "fausse-cle")
    monkeypatch.setattr("tp2.utils.llm.requests.post", faux_post)

    assert appeler_llm("test") is None


VERDICT_OK = {
    "famille": "dropper",
    "capacites": ["telechargement"],
    "mitre_attack": ["T1071"],
    "score_0_10": 7,
    "iocs": {"domains": ["c2.example.test"]},
}


def test_valider_verdict_json_entoure():
    """
    vérifie qu'un json entouré de texte et de ```json est bien lu
    """
    texte = "Voici mon analyse :\n```json\n" + json.dumps(VERDICT_OK) + "\n```"

    assert valider_verdict(texte) == VERDICT_OK


def test_valider_verdict_pas_du_json():
    """
    vérifie qu'une réponse qui n'est pas du json est refusée
    """
    assert valider_verdict("ce fichier est sain") is None
    assert valider_verdict(None) is None


def test_valider_verdict_cle_manquante():
    """
    vérifie qu'un json auquel il manque une clé est refusé
    """
    assert valider_verdict(json.dumps({"famille": "dropper"})) is None


def test_valider_verdict_score_borne():
    """
    vérifie qu'un score hors bornes est ramené entre 0 et 10
    """
    trop_haut = VERDICT_OK.copy()
    trop_haut["score_0_10"] = 42
    trop_bas = VERDICT_OK.copy()
    trop_bas["score_0_10"] = -5

    assert valider_verdict(json.dumps(trop_haut))["score_0_10"] == 10
    assert valider_verdict(json.dumps(trop_bas))["score_0_10"] == 0


def test_llm_triage_bonne_reponse(monkeypatch):
    """
    vérifie que llm_triage renvoie le verdict quand le llm répond un json correct
    """

    def faux_appeler_llm(summary):
        return json.dumps(VERDICT_OK)

    monkeypatch.setattr("tp2.utils.llm.appeler_llm", faux_appeler_llm)

    assert llm_triage("resume") == VERDICT_OK
