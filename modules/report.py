from fpdf import FPDF

class PhishingReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'PhishGuard - Rapport de Menace', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def clean_text(text):
    """
    Fonction vitale : Elle retire tous les caractères que le PDF ne peut pas gérer.
    Elle remplace les emojis connus par du texte, et les inconnus par '?'
    """
    if not isinstance(text, str):
        return str(text)
    
    # 1. Remplacement manuel des emojis qu'on utilise
    replacements = {
        "✅": "[OK]",
        "🔴": "[DANGER]",
        "⚠️": "[WARN]",
        "⚪": "[UNKNOWN]",  # <--- C'était lui le coupable !
        "🟢": "[SAFE]",
        "🟠": "[SUSPECT]",
        "🚨": "[ALERT]"
    }
    
    for emoji, replacement in replacements.items():
        text = text.replace(emoji, replacement)
        
    # 2. Nettoyage final (Force l'encodage Latin-1)
    # Tout caractère bizarre restant deviendra un '?'
    return text.encode('latin-1', 'replace').decode('latin-1')

def generate_pdf(parsed_data, fraud_data, ip_data, vt_data):
    pdf = PhishingReport()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # --- 1. VERDICT ---
    score = fraud_data['score']
    
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, clean_text("1. VERDICT D'ANALYSE"), 0, 1)
    
    pdf.set_font("Arial", "", 11)
    if score > 50:
        pdf.set_text_color(194, 24, 7) # Rouge
        pdf.cell(0, 10, clean_text(f"STATUT: DANGEREUX (Score: {score}/100)"), 0, 1)
    elif score > 0:
        pdf.set_text_color(255, 140, 0) # Orange
        pdf.cell(0, 10, clean_text(f"STATUT: SUSPECT (Score: {score}/100)"), 0, 1)
    else:
        pdf.set_text_color(0, 128, 0) # Vert
        pdf.cell(0, 10, clean_text(f"STATUT: SUR (Score: {score}/100)"), 0, 1)
    
    pdf.set_text_color(0, 0, 0)
    pdf.ln(5)

    # --- 2. DETAILS EMAIL ---
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, clean_text("2. EN-TETES"), 0, 1)
    pdf.set_font("Arial", "", 10)
    
    headers = parsed_data.get('headers', {})
    pdf.multi_cell(0, 7, clean_text(f"Sujet: {headers.get('Subject', 'N/A')}"))
    pdf.multi_cell(0, 7, clean_text(f"De: {headers.get('From', 'N/A')}"))
    pdf.multi_cell(0, 7, clean_text(f"Date: {headers.get('Date', 'N/A')}"))
    pdf.ln(5)

    # --- 3. ALERTES DE FRAUDE ---
    if fraud_data['alerts']:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, clean_text("3. ANOMALIES DETECTEES"), 0, 1)
        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(194, 24, 7)
        for alert in fraud_data['alerts']:
            pdf.cell(0, 7, clean_text(f"- {alert}"), 0, 1)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)

    # --- 4. GEO-LOCALISATION ---
    if ip_data:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, clean_text("4. INFRASTRUCTURE & RESEAU"), 0, 1)
        pdf.set_font("Arial", "", 10)
        for loc in ip_data:
            line = f"- IP: {loc['ip']} -> {loc['city']}, {loc['country']} ({loc['isp']})"
            pdf.cell(0, 7, clean_text(line), 0, 1)
        pdf.ln(5)

    # --- 5. LIENS MALVEILLANTS ---
    if vt_data:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, clean_text("5. ANALYSE DES LIENS (URLS)"), 0, 1)
        pdf.set_font("Arial", "", 8)
        for item in vt_data:
            status = item.get('status', 'Inconnu')
            url = item.get('url', 'N/A')
            # On passe tout par clean_text
            line = f"[{status}] {url}"
            pdf.multi_cell(0, 6, clean_text(line))
        pdf.ln(5)

    # Export
    return pdf.output(dest='S').encode('latin-1', 'replace')