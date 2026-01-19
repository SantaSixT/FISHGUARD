import streamlit as st
from streamlit_folium import st_folium

# Imports Modules
from modules.parser import EmailParser
from modules.analyzer import FraudDetector
from modules.geolocation import get_ip_location, generate_map
from modules.tracer import trace_url
from modules.report import generate_pdf
from modules.urlscan import UrlScanRadar
from modules.abuseipdb import check_ip_reputation

# Config
st.set_page_config(page_title="PhishGuard Ultimate", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .main-title { font-size: 3em; color: #4CAF50; text-align: center; font-weight: bold; }
    .stTextArea textarea { font-size: 0.8em; font-family: 'Courier New', monospace; background-color: #111; color: #0f0; }
    .alert-box { border: 1px solid #ff4b4b; background-color: #2e1111; padding: 10px; border-radius: 5px; color: #ff4b4b; }
    .clean-box { border: 1px solid #00ff41; background-color: #112e11; padding: 10px; border-radius: 5px; color: #00ff41; }
</style>
""", unsafe_allow_html=True)

st.markdown('<h1 class="main-title">🛡️ PhishGuard</h1>', unsafe_allow_html=True)

# Cache
if 'scan_results' not in st.session_state:
    st.session_state['scan_results'] = None

col1, col2 = st.columns([1, 1])

# --- GAUCHE : INPUT (ONGLETS) ---
with col1:
    st.subheader("📨 Entrée")
    
    # Onglets pour choisir le mode d'entrée
    tab_text, tab_file = st.tabs(["📝 Copier-Coller", "📂 Fichier (.eml/.msg)"])
    
    scan_triggered = False
    input_content = None
    input_type = "text" # 'text', 'eml', 'msg'

    with tab_text:
        raw_text = st.text_area("Code source du mail", height=400, key="email_text_input")
        if st.button("🔍 SCANNER TEXTE", type="primary", use_container_width=True):
            if raw_text:
                scan_triggered = True
                input_content = raw_text
                input_type = "text"
            else:
                st.warning("Zone vide.")

    with tab_file:
        uploaded_file = st.file_uploader("Glissez votre mail ici", type=['eml', 'msg'])
        if st.button("🔍 SCANNER FICHIER", type="primary", use_container_width=True, key="btn_file"):
            if uploaded_file:
                scan_triggered = True
                input_content = uploaded_file
                # Détection extension
                if uploaded_file.name.endswith('.msg'):
                    input_type = "msg"
                else:
                    input_type = "eml"
            else:
                st.warning("Aucun fichier choisi.")

    # LOGIQUE DE SCAN (CENTRALISÉE)
    if scan_triggered:
        parser = EmailParser()
        detector = FraudDetector()
        url_scanner = UrlScanRadar()
        
        with st.spinner("🔄 Dissection et Analyse en cours..."):
            # 1. Parsing (adapté au type)
            parsed = parser.parse(input_content, source_type=input_type)
            
            if parsed["status"] == "success":
                # 2. Fraude
                fraud_res = detector.analyze(parsed["headers"], parsed["body_preview"])
                
                # 3. Infra
                ips = parsed["headers"].get("Received-IPs", [])
                ip_reports = [check_ip_reputation(ip) for ip in ips]
                ip_locations = [loc for loc in [get_ip_location(ip) for ip in ips] if loc]
                
                # 4. URLs
                urls = parsed["urls"]
                url_report = None
                trace_report = None
                if urls:
                    trace_report = trace_url(urls[0])
                    url_report = url_scanner.scan(urls[0])

                # Sauvegarde Mémoire
                st.session_state['scan_results'] = {
                    "parsed": parsed,
                    "fraud": fraud_res,
                    "ip_reports": ip_reports,
                    "ip_locations": ip_locations,
                    "url_report": url_report,
                    "trace_report": trace_report,
                    "urls": urls
                }
            else:
                st.error(f"Erreur technique : {parsed['message']}")

# --- DROITE : RAPPORT ---
with col2:
    st.subheader("📊 Rapport Tactique")
    results = st.session_state['scan_results']
    
    if results:
        parsed = results["parsed"]
        fraud = results["fraud"]
        
        # 1. VERDICT
        score_color = "red" if fraud["score"] > 50 else "orange" if fraud["score"] > 0 else "green"
        st.markdown(f"### Verdict: :{score_color}[{fraud['verdict']}]")
        st.progress(min(fraud["score"], 100))
        
        for alert in fraud["alerts"]:
            st.markdown(f"<div class='alert-box'>🚨 {alert}</div>", unsafe_allow_html=True)
            
        st.divider()

        # 2. PIÈCES JOINTES (NOUVEAU !)
        st.markdown("### 📎 Pièces Jointes & Virus")
        attachments = parsed.get("attachments", [])
        if attachments:
            for att in attachments:
                with st.expander(f"📄 {att['filename']} ({att['size']} bytes)"):
                    st.code(att['hash'], language='text')
                    # Lien magique VirusTotal (Marche sans API Key !)
                    vt_link = f"https://www.virustotal.com/gui/file/{att['hash']}"
                    st.markdown(f"👉 [Vérifier ce Hash sur VirusTotal]({vt_link})", unsafe_allow_html=True)
                    st.caption("Si VirusTotal connaît ce fichier, il vous dira si c'est un virus.")
        else:
            st.info("Aucune pièce jointe détectée.")

        st.divider()

        # 3. SANDBOX URL
        st.markdown("### 📸 Sandbox & Liens")
        url_rep = results["url_report"]
        if url_rep and url_rep.get('status') == 'success':
            st.image(url_rep['screenshot'], use_container_width=True)
            if url_rep['malicious']: st.error("🚨 SITE MALVEILLANT !")
            else: st.success("✅ Site Sain")
        elif not results["urls"]:
            st.info("Pas de liens.")
        else:
            st.warning("Scan visuel indisponible.")

        st.divider()

        # 4. INFRA
        st.markdown("### 🌍 Origine")
        if results["ip_locations"]:
            m = generate_map(results["ip_locations"])
            if m: st_folium(m, height=250, width=700)
        else:
            st.info("Localisation impossible.")

        # PDF
        pdf_data = generate_pdf(parsed, fraud, results["ip_locations"], [])
        st.download_button("📄 Rapport PDF", pdf_data, "rapport.pdf", "application/pdf")

    else:
        st.info("En attente d'un mail...")