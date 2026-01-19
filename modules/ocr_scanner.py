try:
    from PIL import Image
    import pytesseract
    # Décommente la ligne ci-dessous si tu es sur Windows et que Tesseract n'est pas dans le PATH
    # pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False

def scan_image_for_text(image_file):
    """Extrait le texte d'une image via Tesseract OCR"""
    if not OCR_AVAILABLE:
        return "Module OCR non disponible (Installer Tesseract)"
    
    try:
        text = pytesseract.image_to_string(Image.open(image_file))
        return text.strip() if text else "Aucun texte détecté."
    except Exception as e:
        return f"Erreur lecture image: {str(e)}"