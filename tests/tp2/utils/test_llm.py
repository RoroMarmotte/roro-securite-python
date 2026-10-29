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
