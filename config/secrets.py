import os
from dotenv import load_dotenv

# 1. On charge les variables du fichier .env dans le système
load_dotenv()

# 2. On récupère la clé de manière sécurisée
# Si la clé n'est pas trouvée, ça renverra None (et le radar le gérera)
VT_API_KEY = os.getenv("VT_API_KEY")