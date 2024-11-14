from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

import base64
import datetime
from urllib.parse import urlparse

class draftVerifier:
    def generate_digest(body):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(body.encode("utf-8") if not isinstance(body, bytes) else body)
        hash_bytes = digest.finalize()
        return "SHA-256=" + base64.b64encode(hash_bytes).decode("utf-8")


    def verify(public_pem: str, method: str, url: str, headers: dict, body: bytes=b""):
        signature_header = headers.get("signature")
        if not signature_header:
            return False, "Signature header is missing"

        signature_parts = {}
        for item in signature_header.split(","):
            key, value = item.split("=", 1)
            signature_parts[key.strip()] = value.strip().strip('"')

        signature = base64.b64decode(signature_parts["signature"])
        #keyId = signature_parts["keyId"]
        algorithm = signature_parts["algorithm"]

        if algorithm != "rsa-sha256":
            return False, "Unsupported algorithm"

        signed_headers = signature_parts["headers"].split()

        parsed_url = urlparse(url)
        request_target = f"(request-target): {method.lower()} {parsed_url.path}"

        signature_headers = [request_target]
        for header in signed_headers:
            if header in headers:
                signature_headers.append(f"{header}: {headers[header]}")

        signature_string = "\n".join(signature_headers).encode("utf-8")

        public_key = serialization.load_pem_public_key(
            public_pem.encode('utf-8'),
            backend=default_backend()
        )

        try:
            public_key.verify(
                signature, signature_string, padding.PKCS1v15(), hashes.SHA256()
            )
        except InvalidSignature:
            return False, "Invalid signature"

        expected_digest = draftVerifier.generate_digest(body)
        if headers.get("digest") != expected_digest:
            return False, "Digest mismatch"

        date_header = headers.get("date")
        if date_header:
            request_time = datetime.datetime.strptime(
                date_header, "%a, %d %b %Y %H:%M:%S GMT"
            )
            current_time = datetime.datetime.utcnow()
            if abs((current_time - request_time).total_seconds()) > 3600:
                return False, "Date header is too far from current time"

        return True, "Signature is valid"
