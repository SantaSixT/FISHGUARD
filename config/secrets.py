# config/secrets.py
import os
from dotenv import load_dotenv

load_dotenv()

# On charge toutes les clés
URLSCAN_KEY = os.getenv("URLSCAN_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")