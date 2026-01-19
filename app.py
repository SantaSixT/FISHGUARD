import streamlit as st
from streamlit_folium import st_folium

# Imports des modules internes
from modules.parser import EmailParser
from modules.radar import VirusTotalRadar
from modules.analyzer import FraudDetector
from modules.geolocation import get_ip_location, generate_map
from modules.tracer import trace_url

# Config
st.set_page_config(page_title="PhishGuard Elite", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .main-title { font-size: 3em; color: #4CAF50; text-align: center; font-weight: bold; }
    .stTextArea textarea { font-size: 0.8em; font-family: 'Courier New', monospace; background-color: #111; color: #0f0; }
    .alert-box { border: 1px solid #ff4b4b; background-color: #2e1111; padding: 10px; border-radius: 5px; color: #ff4b4b; }
    .clean-box { border: 1px solid #00ff41; background-color: #112e11; padding: 10px; border-radius: 5px; color: #00ff41; }
    .redirect-arrow { font-size: 1.2em; color: #f39c12; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

st.markdown('<h1 class="main-title">🛡️ PhishGuard</h1>', unsafe_allow_html=True)

# --- GESTION DE LA MÉMOIRE (Pour que les résultats restent affichés) ---
if 'analysis_active' not in st.session_state:
    st.session_state['analysis_active'] = False

col1, col2 = st.columns([1, 1])

# --- GAUCHE : INPUT ---
with col1:
    st.subheader("📨 Entrée")
    # On ajoute key="email_input" pour ne pas perdre le texte
    raw_email = st.text_area("Code source du mail", height=600, key="email_input", help="Copiez le header + body ici")
    
    # Quand on clique, on active la mémoire
    if st.button("🔍 SCANNER MAINTENANT", type="primary", use_container_width=True):
        st.session_state['analysis_active'] = True

# --- DROITE : RAPPORT ---
with col2:
    st.subheader("📊 Rapport Tactique")
    
    # On vérifie la MÉMOIRE (session_state) au lieu du simple clic
    if st.session_state['analysis_active'] and raw_email:
        
        # 1. INITIALISATION
        parser = EmailParser()
        radar = VirusTotalRadar()
        detector = FraudDetector()
        
        # Note : Dans une version optimisée, on mettrait aussi les résultats en cache 
        # pour éviter de tout recalculer au zoom. Pour l'instant, ça relance l'analyse.
        
        with st.spinner("🔄 Analyse cybernétique en cours..."):
            # A. PARSING
            parsed = parser.parse(raw_email)
            
            if parsed["status"] == "success":
                # B. LOGIQUE
                fraud_res = detector.analyze(parsed["headers"], parsed["body_preview"])
                
                # --- AFFICHAGE VERDICT ---
                score_color = "red" if fraud_res["score"] > 50 else "orange" if fraud_res["score"] > 0 else "green"
                st.markdown(f"### Verdict: :{score_color}[{fraud_res['verdict']}]")
                st.progress(min(fraud_res["score"], 100))
                
                # ALERTES
                if fraud_res["alerts"]:
                    for alert in fraud_res["alerts"]:
                        st.markdown(f"<div class='alert-box'>🚨 {alert}</div>", unsafe_allow_html=True)
                else:
                    st.markdown("<div class='clean-box'>✅ Aucune anomalie sémantique détectée</div>", unsafe_allow_html=True)
                
                st.divider()

                # --- C. RADAR & TRACEUR (OPTION C) ---
                st.markdown("### 📡 Analyse des Liens (Traceur & VT)")
                urls = parsed["urls"]
                
                if urls:
                    # On scanne avec VirusTotal
                    vt_res = radar.scan_urls(urls)
                    
                    for i, url in enumerate(urls):
                        # On lance le traceur de redirection
                        trace = trace_url(url)
                        vt_info = vt_res[i] if i < len(vt_res) else {"status": "Non scanné", "score": 0}
                        
                        icon = "🔴" if "DANGER" in vt_info['status'] else "✅"
                        
                        with st.expander(f"{icon} {url[:40]}..."):
                            # Affichage Traceur
                            if trace['redirect_count'] > 0:
                                st.warning(f"⚠️ {trace['redirect_count']} Redirection(s) détectée(s) !")
                                for hop in trace['chain']:
                                    st.text(f"↪ {hop}")
                                st.markdown(f"**Destination finale :** `{trace['final']}`")
                            else:
                                st.success("Lien direct (Pas de redirection cachée)")
                            
                            st.write("---")
                            # Affichage VirusTotal
                            st.write(f"**Statut VirusTotal:** {vt_info['status']}")
                            st.write(f"**Moteurs Positifs:** {vt_info['score']}")

                else:
                    st.info("Aucun lien à scanner.")

                st.divider()

                # --- D. CARTOGRAPHIE (OPTION A) ---
                st.markdown("### 🌍 Origine de l'attaque")
                ips = parsed["headers"].get("Received-IPs", [])
                
                if ips:
                    ip_locations = []
                    for ip in ips:
                        loc = get_ip_location(ip)
                        if loc: ip_locations.append(loc)
                    
                    if ip_locations:
                        m = generate_map(ip_locations)
                        if m:
                            st_folium(m, height=300, width=700)
                            for loc in ip_locations:
                                st.caption(f"📍 **{loc['country']}, {loc['city']}** (ISP: {loc['isp']}) - IP: {loc['ip']}")
                    else:
                        st.warning("Impossible de géolocaliser les IPs trouvées.")
                else:
                    st.info("Aucune IP extractible dans les headers.")

                # DONNÉES TECHNIQUES
                with st.expander("📝 En-têtes Bruts"):
                    st.json(parsed["headers"])

            else:
                st.error("Erreur de parsing.")

    elif st.session_state['analysis_active'] and not raw_email:
        st.warning("⚠️ Veuillez coller un mail.")