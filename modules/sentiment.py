from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
from deep_translator import GoogleTranslator

class SentimentScanner:
    def __init__(self):
        self.analyzer = SentimentIntensityAnalyzer()
        # On initialise le traducteur
        self.translator = GoogleTranslator(source='auto', target='en')

    def analyze(self, text):
        """
        Traduit le texte en anglais puis analyse la pression psychologique.
        """
        if not text or len(text) < 5:
            return {"score": 0, "verdict": "⚪ Neutre (Vide)", "color": "gray"}

        try:
            # 1. TRADUCTION (La clé du succès)
            # On coupe le texte s'il est trop long pour la traduction rapide (max 1000 chars)
            text_to_translate = text[:999]
            translated_text = self.translator.translate(text_to_translate)
        except Exception:
            # Si pas d'internet ou erreur de traduction, on garde le texte original
            translated_text = text

        # 2. ANALYSE VADER (Sur le texte en ANGLAIS)
        scores = self.analyzer.polarity_scores(translated_text)
        compound = scores['compound']
        
        # 3. VERDICT
        # Le score va de -1 (Très Négatif) à +1 (Très Positif)
        
        # On ajuste les seuils pour être plus sensible aux menaces
        if compound <= -0.3: 
            verdict = "🔴 DANGER : Menace / Pression / Peur"
            color = "red"
        elif compound <= -0.05:
            verdict = "🟠 Suspect : Ton Négatif"
            color = "orange"
        elif compound >= 0.8:
            verdict = "🟠 Suspect : Euphorie excessive (Appât)"
            color = "orange"
        else:
            verdict = "🟢 Ton Neutre / Informatif"
            color = "green"

        return {
            "score": compound, 
            "verdict": verdict,
            "color": color,
            "translated_preview": translated_text[:50] + "..." # Pour debug si besoin
        }