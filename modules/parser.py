import mailparser
import re
import hashlib
import extract_msg # Nouvelle librairie pour les .msg
import tempfile
import os

class EmailParser:
    def __init__(self):
        pass

    def get_sha256(self, content):
        """Calcule l'empreinte numérique (Hash) d'un fichier"""
        if isinstance(content, str):
            content = content.encode('utf-8')
        return hashlib.sha256(content).hexdigest()

    def parse(self, input_data, source_type="text"):
        """
        input_data : Peut être du texte ou un fichier uploadé
        source_type : 'text', 'eml', ou 'msg'
        """
        try:
            mail = None
            attachments_found = []

            # A. CAS 1 : Texte Copié-Collé
            if source_type == "text":
                mail = mailparser.parse_from_string(input_data)

            # B. CAS 2 : Fichier .EML
            elif source_type == "eml":
                # input_data est un objet BytesIO de Streamlit
                mail = mailparser.parse_from_bytes(input_data.getvalue())

            # C. CAS 3 : Fichier .MSG (Outlook)
            elif source_type == "msg":
                # extract-msg a besoin d'un vrai fichier sur le disque parfois, 
                # ou gère le BytesIO différemment.
                with tempfile.NamedTemporaryFile(delete=False, suffix=".msg") as tmp:
                    tmp.write(input_data.getvalue())
                    tmp_path = tmp.name
                
                msg = extract_msg.Message(tmp_path)
                
                # On convertit le format MSG vers notre format standard
                headers = {}
                for k, v in msg.header.items():
                    headers[k] = v
                
                # Simulation d'objet pour garder la compatibilité
                class MockMail:
                    def __init__(self, msg_obj):
                        self.headers = msg_obj.header
                        self.subject = msg_obj.subject
                        self.from_ = [(msg_obj.sender, msg_obj.sender)] # Format simplifié
                        self.to = [(msg_obj.to, msg_obj.to)]
                        self.date = msg_obj.date
                        self.text_plain = [msg_obj.body]
                        self.text_html = [msg_obj.htmlBody] if msg_obj.htmlBody else []
                        self.attachments = [] # On gère les PJ manuellement après

                mail = MockMail(msg)
                
                # Gestion PJ pour MSG
                for att in msg.attachments:
                    if hasattr(att, 'data'):
                        attachments_found.append({
                            "filename": att.longFilename or att.shortFilename,
                            "hash": self.get_sha256(att.data),
                            "size": len(att.data)
                        })
                
                msg.close()
                os.unlink(tmp_path) # Nettoyage

            # --- EXTRACTION COMMUNE ---
            
            # 1. Headers
            # Adaptation car mailparser et extract-msg rangent les headers différemment
            h_dict = mail.headers if isinstance(mail.headers, dict) else {}
            
            # Fallback pour mailparser qui parfois met les headers dans des attributs directs
            subject = getattr(mail, 'subject', '')
            date = getattr(mail, 'date', '')
            from_ = getattr(mail, 'from_', [])
            to_ = getattr(mail, 'to', [])

            # Conversion propre des listes d'emails en string
            str_from = str(from_[0][0]) if from_ and isinstance(from_, list) and from_[0] else str(from_)
            str_to = str(to_[0][0]) if to_ and isinstance(to_, list) and to_[0] else str(to_)

            headers_clean = {
                "Subject": subject,
                "From": str_from,
                "To": str_to,
                "Date": str(date),
                "Received-IPs": self.extract_ips(str(h_dict) + str(input_data if source_type == 'text' else '')) 
            }

            # 2. Corps
            body_text = mail.text_plain[0] if mail.text_plain else ""
            body_html = mail.text_html[0] if mail.text_html else ""
            full_body = body_text + " " + (body_html.decode("utf-8") if isinstance(body_html, bytes) else str(body_html))

            # 3. URLs
            urls = self.extract_urls(full_body)

            # 4. Pièces Jointes (Si pas déjà traitées par le bloc MSG)
            if source_type != "msg" and hasattr(mail, 'attachments'):
                for att in mail.attachments:
                    # mailparser retourne les PJ en dict souvent base64
                    payload = att.get('payload')
                    if payload:
                        # Si c'est encodé en base64, il faudrait le décoder pour avoir le vrai hash
                        # Pour simplifier ici, on hash le contenu brut récupéré
                        import base64
                        try:
                            content = base64.b64decode(payload)
                        except:
                            content = str(payload).encode()
                            
                        attachments_found.append({
                            "filename": att.get('filename', 'inconnu'),
                            "hash": self.get_sha256(content),
                            "size": len(content)
                        })

            return {
                "status": "success",
                "headers": headers_clean,
                "body_preview": body_text[:500] + "...",
                "urls": urls,
                "attachments": attachments_found
            }

        except Exception as e:
            return {"status": "error", "message": str(e)}

    def extract_urls(self, text):
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'
        found = re.findall(url_pattern, text)
        return list(set(found))

    def extract_ips(self, text):
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        public_ips = [ip for ip in set(ips) if not ip.startswith(("127.", "10.", "192.168.", "172.16."))]
        return list(public_ips)