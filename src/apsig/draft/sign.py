from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from pyfill import datetime
import base64
from urllib.parse import urlparse

class draftSigner:
    def _generate_digest(body: bytes | str):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(body.encode("utf-8") if isinstance(body, str) else body)
        hash_bytes = digest.finalize()
        return "SHA-256=" + base64.b64encode(hash_bytes).decode("utf-8")

    @staticmethod
    def sign(private_key: rsa.RSAPrivateKey, method: str, url: str, headers: dict, key_id: str, body: bytes="") -> dict:
        """Signs an HTTP request with a digital signature.

        Args:
            private_key (rsa.RSAPrivateKey): The RSA private key used to sign the request.
            method (str): The HTTP method (e.g., "GET", "POST").
            url (str): The URL of the request.
            headers (dict): A dictionary of HTTP headers that will be signed.
            key_id (str): The key identifier to include in the signature header.
            body (bytes, optional): The request body. Defaults to an empty byte string.

        Returns:
            dict: The HTTP headers with the signature added.

        Raises:
            ValueError: If the signing process fails due to invalid parameters.
        """
        parsed_url = urlparse(url)
        request_target = f"(request-target): {method.lower()} {parsed_url.path}"

        digest = draftSigner._generate_digest(body)

        headers["digest"] = digest
        headers["date"] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

        signature_headers = [request_target]
        for header in headers:
            signature_headers.append(f"{header}: {headers[header]}")

        signature_string = "\n".join(signature_headers).encode("utf-8")

        signature = private_key.sign(signature_string, padding.PKCS1v15(), hashes.SHA256())
        signature_b64 = base64.b64encode(signature).decode("utf-8")
        header_keys = []
        for key in headers.keys():
            #if key.lower() != "content-type":
            header_keys.append(key)

        if not headers.get("Host"):
            headers["Host"] = parsed_url.netloc
        signature_header = f'keyId="{key_id}",algorithm="rsa-sha256",headers="(request-target) {" ".join(header_keys)}",signature="{signature_b64}"'
        headers["Signature"] = signature_header
        headers["Authorization"] = f"Signature {signature_header}" # Misskeyなどでは必要
        return headers
