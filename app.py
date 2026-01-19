import streamlit as st

# Configuration de la page
st.set_page_config(page_title="PhishGuard V1", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .main-title { font-size: 3em; color: #4CAF50; text-align: center; }
    .stTextArea textarea { font-size: 0.8em; font-family: monospace; }
</style>
""", unsafe_allow_html=True)

st.markdown('<h1 class="main-title">🛡️ PhishGuard</h1>', unsafe_allow_html=True)
st.markdown("### Analyseur de Menaces E-mail & Phishing")
st.markdown("---")

# Zone gauche (Entrée) / Zone droite (Résultats)
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("📨 Courrier Suspect")
    raw_email = st.text_area("Collez le code source du mail ici (Header + Body)", height=400, placeholder="Delivered-To: victime@gmail.com\nReceived: from unknown...")
    
    analyze_btn = st.button("🔍 ANALYSER LA MENACE", use_container_width=True)

with col2:
    st.subheader("📊 Rapport d'Investigation")
    
    if analyze_btn and raw_email:
        # Placeholder pour les futurs modules
        st.info("🧬 Démarrage du Dissecteur...")
        st.write("---")
        
        # Simulation d'affichage (pour l'instant)
        st.error("🚨 ALERTE : Ce mail contient des éléments suspects.")
        
        with st.expander("📡 Radar API (VirusTotal)", expanded=True):
            st.write("Analyse des liens en cours... (À coder)")
            
        with st.expander("🧠 Analyseur de Fraude"):
            st.write("Vérification Typosquatting... (À coder)")
            
    elif analyze_btn:
        st.warning("Veuillez coller un mail pour commencer.")
    else:
        st.info("En attente d'un échantillon...")