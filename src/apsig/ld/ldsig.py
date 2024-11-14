# jsonld_signature.py

from pyld import jsonld
from nacl.signing import SigningKey
import hashlib
import json
import base64
from datetime import datetime
from email.utils import formatdate
from nacl.exceptions import BadSignatureError
from urllib.parse import urlparse

class JSONLDSigner:
    def __init__(self):
        self.signing_key = SigningKey.generate()
        self.verify_key = self.signing_key.verify_key

    def sign(self, data, headers, method: str, url: str, key_id: str):
        normalized_data = jsonld.normalize(data, {'algorithm': 'URDNA2015', 'format': 'application/n-quads'})

        date_header = formatdate(timeval=None, localtime=False, usegmt=True)
        digest = 'SHA-256=' + base64.b64encode(hashlib.sha256(normalized_data.encode('utf-8')).digest()).decode()
        parsed_url = urlparse(url)

        headers['date'] = date_header
        headers['digest'] = digest
        headers['(request-target)'] = f'{method.lower()} {parsed_url.path}'
        
        signed_headers = " ".join(headers.keys())
        signature_base = "\n".join(f"{k}: {v}" for k, v in headers.items())

        signature = self.signing_key.sign(signature_base.encode('utf-8'))

        signature_header = {
            'keyId': key_id,
            'algorithm': 'hs2019',
            'headers': signed_headers,
            'signature': base64.b64encode(signature.signature).decode()
        }

        return signature_header, normalized_data

    def verify(self, signature_header, normalized_data, headers):
        signature_bytes = base64.b64decode(signature_header['signature'])
        signed_headers = signature_header['headers'].split()
        if len(signature_bytes) != 64:
            return False
        headers['date'] = formatdate(timeval=None, localtime=False, usegmt=True)
        digest = 'SHA-256=' + base64.b64encode(hashlib.sha256(normalized_data.encode('utf-8')).digest()).decode()
        headers['digest'] = digest
        
        signature_base = "\n".join(f"{k}: {v}" for k, v in headers.items())

        try:
            self.verify_key.verify(signature_base.encode('utf-8'), signature_bytes)
            return True
        except BadSignatureError:
            return False
