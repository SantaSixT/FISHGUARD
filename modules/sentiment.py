from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

class SentimentScanner:
    def __init__(self):
        self.analyzer = SentimentIntensityAnalyzer()

    def analyze(self, text):
        """
        Analyse la pression psychologique du texte.
        Retourne un score de -1 (Très Négatif/Pression) à +1 (Très Positif).
        """
        if not text:
            return {"score": 0, "verdict": "⚪ Neutre (Vide)"}

        # VADER calcule 4 scores : neg, neu, pos, compound (global)
        scores = self.analyzer.polarity_scores(text)
        compound = scores['compound']
        
        # Interprétation pour le Phishing
        # Les arnaques utilisent souvent la peur (Négatif) ou l'appât du gain (Trop Positif "Vous avez gagné !")
        
        if compound <= -0.4:
            verdict = "🔴 DANGER : Pression / Menace / Peur"
            color = "red"
        elif compound <= -0.05:
            verdict = "🟠 Suspect : Ton Négatif"
            color = "orange"
        elif compound >= 0.7:
            verdict = "🟠 Suspect : Euphorie (Appât du gain ?)"
            color = "orange"
        else:
            verdict = "🟢 Ton Neutre / Informatif"
            color = "green"

        return {
            "score": compound, # De -1.0 à 1.0
            "verdict": verdict,
            "details": scores, # neg, neu, pos
            "color": color
        }