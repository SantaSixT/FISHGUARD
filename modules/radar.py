import requests
import base64
try:
    from config.secrets import VT_API_KEY
except ImportError:
    VT_API_KEY = ""

class VirusTotalRadar:
    def __init__(self):
        self.api_key = VT_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3/urls"

    def scan_urls(self, urls):
        """Scanne une liste d'URLs via VirusTotal"""
        results = []
        
        if not self.api_key:
            return [{"url": "N/A", "score": 0, "status": "⚠️ Clé API manquante"}]

        # On limite à 3 URLs pour ne pas bloquer le compte gratuit (4 requêtes/min)
        for url in urls[:3]: 
            try:
                # 1. On encode l'URL en Base64 (requis par VT)
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                
                # 2. On demande le rapport
                headers = {"x-apikey": self.api_key}
                response = requests.get(f"{self.base_url}/{url_id}", headers=headers, timeout=5)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    malicious = stats['malicious']
                    total = malicious + stats['harmless'] + stats['undetected']
                    
                    status = "✅ Clean"
                    if malicious > 0: status = f"🔴 DANGER ({malicious} moteurs)"
                    
                    results.append({"url": url, "score": malicious, "status": status})
                elif response.status_code == 404:
                    results.append({"url": url, "score": 0, "status": "⚪ Inconnu (Jamais scanné)"})
                else:
                    results.append({"url": url, "score": 0, "status": f"Erreur {response.status_code}"})
                    
            except Exception as e:
                results.append({"url": url, "score": 0, "status": "Erreur connexion"})
        
        return results