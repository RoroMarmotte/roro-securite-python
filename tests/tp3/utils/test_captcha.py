import io

from PIL import Image, ImageDraw, ImageFont

from tp3.utils.captcha import resoudre_captcha


def _image(code: str) -> bytes:
    """petite aide : fabrique une image de captcha (texte noir sur fond blanc) comme le serveur"""
    image = Image.new("RGB", (220, 90), "white")
    ImageDraw.Draw(image).text((20, 25), code, fill="black", font=ImageFont.load_default(size=48))
    tampon = io.BytesIO()
    image.save(tampon, "PNG")
    return tampon.getvalue()


def test_resoudre_captcha_lit_le_code():
    """
    test qu'on relit correctement deux codes différents : l'OCR marche vraiment,
    il ne renvoie pas une valeur en dur
    """
    assert resoudre_captcha(_image("ABC42")) == "ABC42"
    assert resoudre_captcha(_image("7XK9Q")) == "7XK9Q"
