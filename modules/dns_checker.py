import dns.resolver

def check_dns_security(domain):
    """Vérifie les enregistrements SPF et DMARC."""
    results = {"spf": "❌ Absent", "dmarc": "❌ Absent"}
    try:
        # Check SPF
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if "v=spf1" in txt:
                results["spf"] = "✅ Présent"
        
        # Check DMARC
        try:
            dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in dmarc_answers:
                txt = rdata.to_text().strip('"')
                if "v=DMARC1" in txt:
                    results["dmarc"] = "✅ Présent"
        except:
            pass
            
    except Exception:
        pass # Erreur DNS ou pas de domaine
        
    return results