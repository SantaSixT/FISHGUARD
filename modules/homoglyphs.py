from confusable_homoglyphs import confusables

def check_homoglyphs(text):
    """Détecte les caractères trompeurs (IDN Homograph Attack)"""
    if not text: return []
    
    found = confusables.is_confusable(text, greedy=True)
    alerts = []
    
    if found:
        for f in found:
            char = f['character']
            homoglyphs = f['homoglyphs']
            if homoglyphs:
                # On ne garde que ceux qui sont vraiment confusants
                alerts.append(f"Caractère trompeur '{char}' (Imite : {homoglyphs[0]['c']})")
            
    return list(set(alerts))