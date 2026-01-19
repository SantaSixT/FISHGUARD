import requests
import time
from config.secrets import URLSCAN_KEY

class UrlScanRadar:
    def __init__(self):
        self.api_key = URLSCAN_KEY
        self.submit_url = "https://urlscan.io/api/v1/scan/"
        self.result_url = "https://urlscan.io/api/v1/result/"

    def scan(self, target_url):
        if not self.api_key:
            return {"status": "error", "message": "Clé URLScan manquante"}

        headers = {"API-Key": self.api_key, "Content-Type": "application/json"}
        data = {"url": target_url, "visibility": "public"}

        try:
            # 1. Demande de scan
            response = requests.post(self.submit_url, headers=headers, json=data)
            if response.status_code != 200:
                return {"status": "error", "message": f"Erreur API ({response.status_code})"}
            
            uuid = response.json()['uuid']
            
            # 2. Attente du résultat (Polling)
            # On attend max 15 secondes (3s * 5 essais)
            for _ in range(5):
                time.sleep(3)
                res = requests.get(f"{self.result_url}{uuid}/")
                
                if res.status_code == 200:
                    data = res.json()
                    stats = data.get('verdicts', {}).get('overall', {})
                    return {
                        "status": "success",
                        "score": stats.get('score', 0),
                        "malicious": stats.get('malicious', False),
                        "screenshot": data['task']['screenshotURL'],
                        "report": data['task']['reportURL'],
                        "domain": data['page']['domain']
                    }
            
            return {"status": "timeout", "message": "Scan trop long, voir rapport plus tard."}

        except Exception as e:
            return {"status": "error", "message": str(e)}