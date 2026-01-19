import re

class FraudDetector:
    def __init__(self):
        self.suspicious_keywords = [
            "urgent", "suspendu", "bloqué", "vérifier", "immédiat", 
            "mot de passe", "password", "facture", "impayé", "securite", "banque"
        ]
        self.legit_domains = ["paypal.com", "google.com", "apple.com", "amazon.com", "impots.gouv.fr"]

    def analyze(self, headers, body):
        alerts = []
        score = 0
        
        # --- CORRECTION ICI ---
        # On force la conversion en chaîne de caractères (str) au cas où c'est une liste
        subject = str(headers.get("Subject", "")).lower()
        sender = str(headers.get("From", "")).lower()
        # ----------------------

        # 1. Détection d'Urgence (Social Engineering)
        for word in self.suspicious_keywords:
            if word in subject or word in body.lower():
                alerts.append(f"⚠️ Langage alarmiste détecté : '{word}'")
                score += 20
                break # On ne compte qu'une fois
        
        # 2. Typosquatting basique
        # Ex: paypaI (i majuscule) au lieu de paypal
        if "paypal" in sender and "paypal.com" not in sender:
            alerts.append("🔴 Typosquatting probable sur 'PayPal'")
            score += 50
        if "amazon" in sender and "amazon.com" not in sender and "amazon.fr" not in sender:
            alerts.append("🔴 Typosquatting probable sur 'Amazon'")
            score += 50
            
        # 3. Incohérence Headers (Spoofing simple)
        
        if score == 0:
            verdict = "🟢 Faible Risque"
        elif score < 50:
            verdict = "🟠 Suspect"
        else:
            verdict = "🔴 HAUTE PROBABILITÉ DE PHISHING"

        return {"score": score, "verdict": verdict, "alerts": alerts}