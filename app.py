import streamlit as st
from streamlit_folium import st_folium
import tldextract

# --- IMPORTS MODULES DE BASE ---
from modules.parser import EmailParser
from modules.analyzer import FraudDetector
from modules.geolocation import get_ip_location, generate_map
from modules.tracer import trace_url
from modules.report import generate_pdf
from modules.urlscan import UrlScanRadar
from modules.abuseipdb import check_ip_reputation

# --- IMPORTS MODULES OMEGA (Avancés) ---
from modules.whois_checker import check_whois
from modules.dns_checker import check_dns_security
from modules.homoglyphs import check_homoglyphs
from modules.route_graph import generate_route_graph
from modules.ocr_scanner import scan_image_for_text
from modules.sentiment import SentimentScanner  # <--- NOUVEAU MODULE

# Config
st.set_page_config(page_title="PhishGuard OMEGA", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .main-title { font-size: 3em; color: #4CAF50; text-align: center; font-weight: bold; }
    .stTextArea textarea { font-size: 0.8em; font-family: 'Courier New', monospace; background-color: #111; color: #0f0; }
    .alert-box { border: 1px solid #ff4b4b; background-color: #2e1111; padding: 10px; border-radius: 5px; color: #ff4b4b; }
    .clean-box { border: 1px solid #00ff41; background-color: #112e11; padding: 10px; border-radius: 5px; color: #00ff41; }
</style>
""", unsafe_allow_html=True)

st.markdown('<h1 class="main-title">🛡️ PhishGuard</h1>', unsafe_allow_html=True)

# Gestion Mémoire
if 'scan_results' not in st.session_state:
    st.session_state['scan_results'] = None

col1, col2 = st.columns([1, 1])

# --- GAUCHE : INPUT ---
with col1:
    st.subheader("📨 Entrée")
    tab_text, tab_file = st.tabs(["📝 Texte", "📂 Fichier"])
    
    scan_triggered = False
    input_content = None
    input_type = "text"

    with tab_text:
        raw_text = st.text_area("Code source", height=400, key="txt_input")
        if st.button("🔍 SCANNER TEXTE", type="primary", use_container_width=True):
            scan_triggered = True; input_content = raw_text; input_type = "text"

    with tab_file:
        uploaded_file = st.file_uploader("Fichier .eml/.msg", type=['eml', 'msg'])
        if st.button("🔍 SCANNER FICHIER", type="primary", use_container_width=True):
            if uploaded_file:
                scan_triggered = True; input_content = uploaded_file
                input_type = "msg" if uploaded_file.name.endswith('.msg') else "eml"
            else:
                st.warning("Aucun fichier sélectionné.")

    if scan_triggered:
        # Initialisation de TOUS les modules
        parser = EmailParser()
        detector = FraudDetector()
        url_scanner = UrlScanRadar()
        sentiment_tool = SentimentScanner() # <--- INIT SENTIMENT
        
        with st.spinner("🔄 Analyse Cybernétique Complète..."):
            parsed = parser.parse(input_content, source_type=input_type)
            
            if parsed["status"] == "success":
                # 1. Analyse Standard & Fraude
                fraud_res = detector.analyze(parsed["headers"], parsed["body_preview"])
                
                # 2. Infra (IPs & Route)
                ips = parsed["headers"].get("Received-IPs", [])
                ip_reports = [check_ip_reputation(ip) for ip in ips]
                ip_locations = [get_ip_location(ip) for ip in ips if get_ip_location(ip)]
                route_viz = generate_route_graph(ips)
                
                # 3. URLs & Domaines (Deep Scan)
                urls = parsed["urls"]
                url_report = None; trace_report = None
                domain_info = None
                
                if urls:
                    target = urls[0]
                    trace_report = trace_url(target)
                    url_report = url_scanner.scan(target)
                    
                    try:
                        ext = tldextract.extract(target)
                        domain = f"{ext.domain}.{ext.suffix}"
                        domain_info = {
                            "name": domain,
                            "whois": check_whois(domain),
                            "dns": check_dns_security(domain)
                        }
                    except: pass

                # 4. Forensics (Homoglyphes + Sentiment)
                # Homoglyphes
                check_txt = parsed["headers"].get("Subject", "") + " " + parsed["headers"].get("From", "")
                homoglyphs = check_homoglyphs(check_txt)
                
                # Sentiment (On analyse Sujet + Corps)
                full_text_ai = f"{parsed['headers'].get('Subject', '')}. {parsed['body_preview']}"
                sentiment_res = sentiment_tool.analyze(full_text_ai)

                # Sauvegarde en mémoire
                st.session_state['scan_results'] = {
                    "parsed": parsed, "fraud": fraud_res,
                    "ip_reports": ip_reports, "ip_locations": ip_locations,
                    "url_report": url_report, "trace_report": trace_report, "urls": urls,
                    "domain_info": domain_info, "homoglyphs": homoglyphs,
                    "route_viz": route_viz,
                    "sentiment": sentiment_res # <--- SAVE SENTIMENT
                }
            else:
                st.error(f"Erreur technique : {parsed['message']}")

# --- DROITE : RAPPORT ---
with col2:
    st.subheader("📊 Rapport Tactique")
    res = st.session_state['scan_results']
    
    if res:
        t1, t2, t3, t4 = st.tabs(["🚫 Verdict", "🌐 Infra/DNS", "🔎 Forensics", "📄 PDF"])
        
        # --- ONGLET 1 : VERDICT ---
        with t1:
            fraud = res["fraud"]
            score_color = "red" if fraud["score"] > 50 else "orange" if fraud["score"] > 0 else "green"
            st.markdown(f"### Score: :{score_color}[{fraud['score']}/100] ({fraud['verdict']})")
            st.progress(min(fraud["score"], 100))
            
            for alert in fraud["alerts"]: st.markdown(f"<div class='alert-box'>🚨 {alert}</div>", unsafe_allow_html=True)
            
            st.divider()
            st.markdown("#### 📸 Sandbox Visuelle")
            if res["url_report"] and res["url_report"].get('status') == 'success':
                st.image(res["url_report"]['screenshot'], caption="Site Cible", use_container_width=True)
                if res["url_report"]['malicious']: st.error("🚨 DÉTECTÉ MALVEILLANT PAR URLSCAN")
                else: st.success("✅ Site Sain selon URLScan")
            elif not res["urls"]:
                st.info("Pas de liens web.")
            else:
                st.warning("Visualisation indisponible.")

        # --- ONGLET 2 : INFRA ---
        with t2:
            if res["domain_info"]:
                di = res["domain_info"]
                st.markdown(f"### 🏢 Domaine : `{di['name']}`")
                c1, c2 = st.columns(2)
                with c1:
                    w = di["whois"]
                    st.markdown("**WHOIS (Âge)**")
                    if "error" in w: st.error(w["error"])
                    else:
                        st.info(f"📅 Création : {w.get('creation_date', '?')}")
                        st.caption(f"Verdict : {w.get('verdict')}")
                with c2:
                    d = di["dns"]
                    st.markdown("**Sécurité DNS**")
                    st.write(f"SPF : {d['spf']}")
                    st.write(f"DMARC : {d['dmarc']}")
                st.divider()

            st.markdown("### 🗺️ Route des Serveurs")
            if res["route_viz"]:
                st.graphviz_chart(res["route_viz"])
            else:
                st.info("Pas assez de données pour le graphique.")

            if res["ip_locations"]:
                m = generate_map(res["ip_locations"])
                if m: st_folium(m, height=200, width=600)
            
            st.markdown("### 🌍 Réputation IPs")
            for rep in res["ip_reports"]:
                # Protection contre l'erreur KeyError si l'API a planté
                ip_addr = rep.get('ip', 'Inconnue')
                country = rep.get('country', 'N/A')
                score = rep.get('score', 0)
                color = "red" if score > 50 else "green"
                st.markdown(f"- **{ip_addr}** ({country}) : :{color}[Score Abuse {score}%]")

        # --- ONGLET 3 : FORENSICS (Avec Sentiment) ---
        with t3:
            # 1. ANALYSE SENTIMENT (VADER)
            st.markdown("### 🧠 Analyse Psychologique (IA Locale)")
            sent = res.get("sentiment", {})
            if sent:
                c_sent1, c_sent2 = st.columns([3, 1])
                with c_sent1:
                    st.markdown(f"**Tonalité détectée :** :{sent['color']}[{sent['verdict']}]")
                    st.caption("Détection mathématique de l'urgence, de la peur ou de l'euphorie.")
                with c_sent2:
                    st.metric("Pression", f"{sent['score']:.2f}")
            else:
                st.info("Analyse de sentiment non disponible.")
            
            st.divider()

            # 2. HOMOGLYPHES
            st.markdown("### 🔤 Homoglyphes")
            if res["homoglyphs"]:
                st.error("⚠️ Caractères trompeurs détectés !")
                for h in res["homoglyphs"]: st.write(f"- {h}")
            else:
                st.success("✅ Aucun caractère trompeur détecté.")
            
            st.divider()
            
            # 3. PIECES JOINTES
            st.markdown("### 📎 Pièces Jointes")
            atts = res["parsed"].get("attachments", [])
            if atts:
                for att in atts:
                    with st.expander(f"📄 {att['filename']} ({att['size']} bytes)"):
                        st.code(f"Hash: {att['hash']}")
                        vt_link = f"https://www.virustotal.com/gui/file/{att['hash']}"
                        st.markdown(f"👉 [Scanner sur VirusTotal]({vt_link})")
            else:
                st.info("Aucune pièce jointe.")

        # --- ONGLET 4 : EXPORT ---
        with t4:
            pdf_data = generate_pdf(res["parsed"], res["fraud"], res["ip_locations"], [])
            st.download_button("📄 Télécharger Rapport PDF Complet", pdf_data, "rapport_omega.pdf", "application/pdf")

    else:
        st.info("En attente d'analyse...")