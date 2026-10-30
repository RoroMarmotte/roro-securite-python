import io

import pytesseract
from PIL import Image


def resoudre_captcha(image_png: bytes) -> str:
    """
    on lit le code du captcha : on passe l'image en noir et blanc pour virer le bruit gris,
    puis pytesseract lit le texte et on garde seulement les lettres et les chiffres
    """
    image = Image.open(io.BytesIO(image_png)).convert("L")
    image = image.point(lambda pixel: 0 if pixel < 128 else 255)
    texte = pytesseract.image_to_string(image, config="--psm 7")
    return "".join(caractere for caractere in texte.upper() if caractere.isalnum())
