from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import base64
from urllib.parse import urlparse

class draftSigner:
    def generate_digest(body):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(body.encode("utf-8"))
        hash_bytes = digest.finalize()
        return "SHA-256=" + base64.b64encode(hash_bytes).decode("utf-8")

    def sign(private_key, method: str, url: str, headers: dict, key_id: str, body: bytes="") -> dict:
        parsed_url = urlparse(url)
        request_target = f"(request-target): {method.lower()} {parsed_url.path}"

        digest = draftSigner.generate_digest(body)
        headers["digest"] = digest

        signature_headers = [request_target]
        for header in headers:
            signature_headers.append(f"{header}: {headers[header]}")

        signature_string = "\n".join(signature_headers).encode("utf-8")

        signature = private_key.sign(signature_string, padding.PKCS1v15(), hashes.SHA256())
        signature_b64 = base64.b64encode(signature).decode("utf-8")

        signature_header = f'keyId="{key_id}",algorithm="rsa-sha256",headers="(request-target) {" ".join(headers.keys())}",signature="{signature_b64}"'
        headers["signature"] = signature_header
        headers["Authorization"] = f"Signature {signature_header}" # Misskeyなどでは必要
        return headers
