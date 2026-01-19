import requests
import os
from dotenv import load_dotenv

load_dotenv()
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")

def check_ip_reputation(ip):
    """Vérifie si une IP est malveillante via AbuseIPDB"""
    
    # Structure de base par défaut (pour éviter les KeyError)
    result = {
        "ip": ip,
        "score": 0,
        "verdict": "Inconnu",
        "country": "N/A",
        "isp": "N/A",
        "domain": "N/A"
    }

    if not ABUSE_KEY:
        result["verdict"] = "Clé Manquante"
        return result

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': ABUSE_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        
        if response.status_code == 200:
            data = response.json()['data']
            score = data.get('abuseConfidenceScore', 0)
            
            # Logique de verdict
            if score == 0: verdict = "✅ Sûr"
            elif score < 50: verdict = "⚠️ Suspect"
            else: verdict = "⛔ DANGEREUX"
            
            return {
                "ip": ip,
                "score": score,
                "verdict": verdict,
                "country": data.get('countryCode', 'N/A'),
                "isp": data.get('isp', 'N/A'),
                "domain": data.get('domain', 'N/A')
            }
        elif response.status_code == 429:
            result["verdict"] = "Quota dépassé"
            return result
        else:
            result["verdict"] = f"Erreur API ({response.status_code})"
            return result
            
    except Exception as e:
        result["verdict"] = "Erreur Connexion"
        return result