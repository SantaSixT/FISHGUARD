# 🛡️ PhishGuard OMEGA
> **L'Arsenal de Cyberdéfense Ultime contre le Phishing.**
> *Analyse Technique, Réputationnelle et Psychologique.*

![PhishGuard Status](https://img.shields.io/badge/Status-Operational-brightgreen)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Streamlit](https://img.shields.io/badge/Framework-Streamlit-red)
![License](https://img.shields.io/badge/License-MIT-gray)

## 📖 Description

**PhishGuard OMEGA** est une plateforme d'analyse de mails suspect (SOC Tool) nouvelle génération. Contrairement aux antivirus classiques qui se basent uniquement sur des signatures, PhishGuard utilise une approche **hybride** :
1.  **Cerveau Gauche (Logique) :** Analyse technique de l'infrastructure (DNS, IP, URLs).
2.  **Cerveau Droit (Psychologique) :** Analyse sémantique par IA pour détecter la pression psychologique et l'urgence.

## ✨ Fonctionnalités Clés

### 🕵️‍♂️ Analyse & Détection
* **Fusion d'Intelligence :** Corrélation entre l'analyse technique et l'analyse de sentiment (VADER + Traduction) pour détecter les menaces invisibles.
* **Fraude Sémantique :** Détection des mots-clés d'urgence, de chantage et d'appât du gain.
* **Forensics Avancé :** Détection d'attaques par Homoglyphes (IDN Spoofing) dans les en-têtes.
* **Scan de Pièces Jointes :** Extraction, calcul de Hash (SHA-256) et lien direct vers VirusTotal.

### 🌐 Infrastructure & Réseau
* **Géolocalisation IP :** Cartographie interactive des serveurs traversés.
* **Réputation IP :** Vérification via **AbuseIPDB** (détection de botnets/proxies).
* **Sécurité DNS :** Audit des enregistrements SPF et DMARC (Anti-Spoofing).
* **Whois Domain :** Analyse de l'ancienneté du nom de domaine (Détection des domaines "Bébés").
* **Graphique de Route :** Visualisation des sauts (Hops) entre les serveurs mail.

### 📸 Sandbox Visuelle
* **URLScan Integration :** Capture d'écran sécurisée du site cible sans cliquer sur le lien.
* **Traceur de Redirection :** Démasquage des liens raccourcis (`bit.ly`, `tinyurl`) jusqu'à la destination finale.

### 🛡️ Sécurité & UX
* **Support Multi-Format :** Analyse de texte brut, fichiers `.eml` et Outlook `.msg`.
* **Anti-XSS :** Assainissement des entrées via `Bleach` pour protéger l'analyste.
* **Rapport PDF :** Génération automatique d'un rapport d'incident téléchargeable.

---

## 🚀 Installation

### Prérequis
* Python 3.9 ou supérieur.
* Un compte (gratuit) sur [AbuseIPDB](https://www.abuseipdb.com/) et [URLScan.io](https://urlscan.io/).
* *(Optionnel)* Tesseract OCR installé sur la machine pour l'analyse d'images.

### 1. Cloner le projet
```bash
git clone [https://github.com/votre-repo/phishguard.git](https://github.com/votre-repo/phishguard.git)
cd phishguard

###2. **Installer les dépendances**
pip install -r requirements.txt

3. Configuration (.env)
Créez un fichier .env à la racine et ajoutez vos clés API :
ABUSEIPDB_API_KEY=votre_cle_ici
URLSCAN_API_KEY=votre_cle_ici

4. Lancer l'application
streamlit run app.py

📂 Structure du Projet
PhishGuard/
├── app.py                 # Cœur de l'application (Interface & Logique)
├── requirements.txt       # Liste des dépendances
├── .env                   # Clés API (Secrets)
└── modules/               # L'Arsenal Modulaire
    ├── parser.py          # Dissecteur d'emails (.eml, .msg)
    ├── analyzer.py        # Moteur de règles statiques
    ├── sentiment.py       # IA Psychologique (Traduction + VADER)
    ├── abuseipdb.py       # Réputation IP
    ├── urlscan.py         # Sandbox Visuelle
    ├── dns_checker.py     # Sécurité DNS (SPF/DMARC)
    ├── whois_checker.py   # Analyse d'âge de domaine
    ├── homoglyphes.py     # Chasseur de caractères trompeurs
    ├── tracer.py          # Traceur de redirections URL
    ├── route_graph.py     # Visualisation Graphviz
    └── report.py          # Générateur PDF

⚠️ Avertissement Légal
Cet outil est destiné à l'analyse de sécurité défensive (Blue Team) et à l'éducation. L'auteur n'est pas responsable de l'utilisation faite de cet outil. Ne scannez jamais des données confidentielles sur des API publiques sans autorisation.

Développé avec ❤️ et du Café par Antoine R 


---

### 🗺️ Roadmap : Synthèse des Améliorations Futures

Voici la liste consolidée de toutes les pistes d'amélioration dont nous avons discuté (implémentées et futures), pour que tu saches exactement où aller ensuite.

#### ✅ Niveau 1 : Déjà Implémenté (Socle Solide)
* Interface Drag & Drop (.eml/.msg).
* Hashage des pièces jointes.
* Analyse de sentiment (IA locale).
* Protection XSS (Bleach).
* API Externes (AbuseIPDB, URLScan).
* Forensics (Homoglyphes).

#### 🚧 Niveau 2 : Prochaines Étapes (Persistance & Ops)
1.  **Tableau de Bord Historique (SQLite) :** Sauvegarder les scans pour faire des statistiques ("Top pays attaquants").
2.  **Dockerisation :** Créer un `Dockerfile` pour lancer l'app en 1 commande partout.
3.  **Authentification :** Ajouter un écran de login robuste pour protéger l'accès à l'outil.

#### 🧠 Niveau 3 : Intelligence Avancée (Cyber Expert)
4.  **Détection de Logo (Computer Vision) :** Utiliser OpenCV pour voir si le logo "PayPal" est présent dans une image.
5.  **LLM Local (Ollama/Mistral) :** Remplacer VADER par une vraie IA conversationnelle ("Explique-moi ce mail").
6.  **Dé-racourcisseur Récursif :** Suivre les liens `bit.ly` -> `tinyurl` -> `site.com` en scannant chaque étape.
7.  **YARA Rules :** Intégrer un moteur de règles YARA pour détecter des signatures de malwares complexes.

#### 👔 Niveau 4 : Professionnalisation (SaaS / SOC)
8.  **Export STIX/JSON :** Pour connecter PhishGuard à des SIEM (outils de sécurité d'entreprise).
9.  **Mode API (FastAPI) :** Séparer le moteur du visuel pour automatiser les scans.
10. **Sanitized HTML View :** Afficher le mail "visuellement" mais dans une sandbox HTML totalement inerte (sans JS).