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
    .score-high { color: #ff4b4b; font-weight: bold; }
    .score-med { color: #ffa500; font-weight: bold; }
    .score-low { color: #00ff41; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

st.markdown('<h1 class="main-title">🛡️ PhishGuard</h1>', unsafe_allow_html=True)

# --- GESTION INTELLIGENTE DE LA MÉMOIRE (CACHE) ---
if 'scan_results' not in st.session_state:
    st.session_state['scan_results'] = None

col1, col2 = st.columns([1, 1])

# --- GAUCHE : INPUT ---
with col1:
    st.subheader("📨 Entrée")
    raw_email = st.text_area("Code source du mail", height=600, key="email_input")
    
    # LE BOUTON LANCE LE CALCUL UNE SEULE FOIS
    if st.button("🔍 SCANNER MAINTENANT", type="primary", use_container_width=True):
        if raw_email:
            # On instancie les outils
            parser = EmailParser()
            detector = FraudDetector()
            url_scanner = UrlScanRadar()
            
            with st.spinner("🔄 Analyse en cours (API & Intelligence)..."):
                # 1. Parsing
                parsed = parser.parse(raw_email)
                
                if parsed["status"] == "success":
                    # 2. Logique Fraude
                    fraud_res = detector.analyze(parsed["headers"], parsed["body_preview"])
                    
                    # 3. IPs & Infra
                    ips = parsed["headers"].get("Received-IPs", [])
                    ip_reports = []
                    ip_locations = []
                    for ip in ips:
                        ip_reports.append(check_ip_reputation(ip))
                        loc = get_ip_location(ip)
                        if loc: ip_locations.append(loc)
                    
                    # 4. URLs
                    urls = parsed["urls"]
                    url_report = None
                    trace_report = None
                    if urls:
                        target = urls[0]
                        trace_report = trace_url(target)
                        url_report = url_scanner.scan(target)

                    # ON SAUVEGARDE TOUT DANS LA MÉMOIRE
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
                    st.error("Erreur de parsing.")
        else:
            st.warning("Veuillez coller un mail.")

# --- DROITE : AFFICHAGE (LECTURE SEULEMENT) ---
with col2:
    st.subheader("📊 Rapport Tactique")
    
    # On récupère les résultats depuis la mémoire (pas de recalcul !)
    results = st.session_state['scan_results']
    
    if results:
        parsed = results["parsed"]
        fraud_res = results["fraud"]
        ip_reports = results["ip_reports"]
        ip_locations = results["ip_locations"]
        url_report = results["url_report"]
        trace_report = results["trace_report"]
        urls = results["urls"]

        # 1. VERDICT
        score_color = "red" if fraud_res["score"] > 50 else "orange" if fraud_res["score"] > 0 else "green"
        st.markdown(f"### Verdict: :{score_color}[{fraud_res['verdict']}]")
        st.progress(min(fraud_res["score"], 100))
        
        if fraud_res["alerts"]:
            for alert in fraud_res["alerts"]:
                st.markdown(f"<div class='alert-box'>🚨 {alert}</div>", unsafe_allow_html=True)
        else:
            st.markdown("<div class='clean-box'>✅ Aucune anomalie sémantique</div>", unsafe_allow_html=True)
        
        st.divider()

        # 2. SANDBOX VISUEL
        st.markdown("### 📸 Sandbox & Liens")
        if url_report and url_report['status'] == 'success':
            # Correction du Warning : on utilise use_container_width
            st.image(url_report['screenshot'], caption=f"Capture: {url_report['domain']}", use_container_width=True)
            
            if url_report['malicious']:
                st.error(f"🚨 URLSCAN: MALVEILLANT (Score: {url_report['score']})")
            else:
                st.success(f"✅ URLSCAN: Site Sain (Score: {url_report['score']})")
                
            with st.expander("Voir détails redirection"):
                    st.write(f"**Final:** {trace_report['final']}")
                    st.write(f"**Redirections:** {trace_report['redirect_count']}")
        
        elif urls:
            st.warning("⚠️ Scan visuel indisponible (Timeout ou Erreur Clé)")
        else:
            st.info("Aucun lien à analyser.")

        st.divider()

        # 3. INFRASTRUCTURE
        st.markdown("### 🌍 Origine & Réputation IP")
        
        if ip_reports:
            for rep in ip_reports:
                color_class = "score-high" if rep['score'] > 50 else "score-low"
                st.markdown(f"""
                **IP:** `{rep['ip']}` ({rep['country']}) - ISP: {rep['isp']}<br>
                Réputation: <span class='{color_class}'>{rep['verdict']} (Confiance Abuse: {rep['score']}%)</span>
                """, unsafe_allow_html=True)
        
        if ip_locations:
            m = generate_map(ip_locations)
            if m: st_folium(m, height=250, width=700)
        else:
            st.info("Pas d'IP exploitable.")

        # 4. EXPORT PDF
        pdf_data = generate_pdf(parsed, fraud_res, ip_locations, [])
        st.download_button("📄 Télécharger Rapport PDF", pdf_data, "rapport.pdf", "application/pdf")

    elif not results:
        st.info("En attente d'analyse...")