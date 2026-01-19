import whois
from datetime import datetime

def check_whois(domain):
    """Vérifie l'âge du domaine. < 30 jours = Danger."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        # Gérer le cas où l'API renvoie une liste
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if not creation_date:
            return {"status": "Inconnu", "verdict": "⚪ Date inconnue"}

        now = datetime.now()
        age = (now - creation_date).days
        
        if age < 30:
            verdict = "🚨 CRITIQUE (Créé il y a < 1 mois)"
        elif age < 365:
            verdict = "⚠️ Récent (< 1 an)"
        else:
            verdict = "✅ Ancien (Fiable)"
        
        return {
            "creation_date": creation_date.strftime('%Y-%m-%d'),
            "registrar": w.registrar,
            "age_days": age,
            "verdict": verdict,
            "domain": domain
        }
    except Exception:
        return {"error": "Domaine introuvable ou erreur WHOIS", "verdict": "⚪ Inconnu"}