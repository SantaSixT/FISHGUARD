import requests
from config.secrets import ABUSE_KEY

def check_ip_reputation(ip):
    """Vérifie si une IP est malveillante via AbuseIPDB"""
    if not ABUSE_KEY:
        return {"score": 0, "verdict": "Clé Manquante", "usage": "N/A"}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': ABUSE_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90' # On regarde l'historique sur 3 mois
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()['data']
            score = data['abuseConfidenceScore'] # 0 à 100
            
            # Interprétation
            if score == 0: verdict = "✅ Sûr"
            elif score < 50: verdict = "⚠️ Suspect"
            else: verdict = "⛔ DANGEREUX"
            
            return {
                "ip": ip,
                "score": score,
                "verdict": verdict,
                "country": data['countryCode'],
                "isp": data['isp'],
                "domain": data['domain']
            }
        else:
            return {"score": 0, "verdict": "Erreur API", "usage": "N/A"}
            
    except Exception:
        return {"score": 0, "verdict": "Erreur Connexion", "usage": "N/A"}