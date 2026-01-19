import requests

def trace_url(url):
    """Suit les redirections (301, 302) pour trouver la vraie destination"""
    hops = []
    try:
        # On fait une requête HEAD (rapide) ou GET en suivant les redirections
        response = requests.get(url, timeout=5, allow_redirects=True)
        
        # On note l'historique (les étapes intermédiaires)
        if response.history:
            for resp in response.history:
                hops.append(f"{resp.status_code} -> {resp.url}")
        
        # L'URL finale
        final_url = response.url
        hops.append(f"🏁 {response.status_code} -> {final_url}")
        
        return {"original": url, "final": final_url, "chain": hops, "redirect_count": len(response.history)}
        
    except Exception as e:
        return {"original": url, "final": "Erreur", "chain": [str(e)], "redirect_count": 0}