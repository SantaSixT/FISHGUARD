import mailparser
import re
from urllib.parse import urlparse

class EmailParser:
    def __init__(self):
        pass

    def parse(self, raw_data):
        """Fonction principale qui pilote l'analyse"""
        try:
            mail = mailparser.parse_from_string(raw_data)
            
            # 1. Extraction des Headers
            headers = {
                "Subject": mail.subject,
                "From": mail.from_,
                "To": mail.to,
                "Date": mail.date,
                "Received-IPs": self.extract_ips(raw_data) # On scanne tout le texte pour les IPs
            }

            # 2. Extraction du Corps (Body)
            body_text = mail.text_plain[0] if mail.text_plain else ""
            body_html = mail.text_html[0] if mail.text_html else ""
            full_body = body_text + " " + body_html

            # 3. Extraction des URLs (le nerf de la guerre)
            urls = self.extract_urls(full_body)

            return {
                "status": "success",
                "headers": headers,
                "body_preview": body_text[:200] + "..." if body_text else "Pas de texte brut.",
                "urls": urls,
                "attachments": mail.attachments
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def extract_urls(self, text):
        """Trouve tous les liens http/https"""
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'
        found = re.findall(url_pattern, text)
        # Nettoyage des doublons
        return list(set(found))

    def extract_ips(self, text):
        """Trouve les adresses IP (IPv4) dans les headers"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        # On filtre les IPs locales (127.0.0.1, etc.) qui ne servent à rien
        public_ips = [ip for ip in set(ips) if not ip.startswith("127.") and not ip.startswith("10.")]
        return list(public_ips)