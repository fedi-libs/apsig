from typing import Any
from typing_extensions import deprecated
import json

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

import base64
from urllib.parse import urlparse, ParseResult
import email.utils

from .tools import calculate_digest, build_string

class draftSigner:
    @staticmethod
    @deprecated("apsig.draft.sign.draftSigner is deprecated; use apsig.draft.sign.Signer instead. This will be removed in apsig 1.0.")
    def sign(private_key: rsa.RSAPrivateKey, method: str, url: str, headers: dict, key_id: str, body: bytes=b"") -> dict:
        signer = Signer(headers=headers, private_key=private_key, method=method, url=url, key_id=key_id, body=body)
        return signer.sign()

class Signer:
    def __init__(self, headers: dict[Any, Any], private_key: rsa.RSAPrivateKey, method: str, url: str, key_id: str, body: bytes | dict=b"") -> None:
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
        if not headers.get("date") and not headers.get("Date"):
            headers["date"] = email.utils.formatdate(usegmt=True)
        self.parsed_url: ParseResult = urlparse(url)
        self.headers = {
            **headers,
            "(request-target)": f"{method.lower()} {self.parsed_url.path}"
        }
        self.private_key = private_key
        self.method = method
        self.url = url
        self.key_id = key_id
        if isinstance(body, dict):
            self.body = json.dumps(body).encode("utf-8")
        else:
            self.body = body
        
        if not self.headers.get("Host"):
            self.headers["Host"] = self.parsed_url.netloc

        if method.upper() != "GET":
            self.__generate_digest(self.body)

    def __generate_sign_header(self, signature: str):
        self.headers["Signature"] = signature
        self.headers["Authorization"] = f"Signature {signature}"

    def __sign_document(self, document: bytes):
        return base64.standard_b64encode(self.private_key.sign(document, padding.PKCS1v15(), hashes.SHA256())).decode("utf-8")

    def __generate_digest(self, body: bytes | str):
        if not self.headers.get("digest") and not self.headers.get("Digest"):
            self.headers["digest"] = calculate_digest(body)
        else:
            return self.headers.get("digest")
    
    def build_signature(self, key_id: str, signature: str, algorithm: str = "rsa-sha256"):
        if algorithm != "rsa-sha256":
            raise NotImplementedError(f"Unsuppored algorithm: {algorithm}")
        
        return ",".join([
            f'keyId="{key_id}"',
            f'algorithm="{algorithm}"',
            f'headers="{" ".join(key.lower() for key in self.headers.keys())}"',
            f'signature="{signature}"'
        ])

    def sign(self) -> dict:
        signature_string = build_string(self.headers).encode("utf-8")
        signature = self.__sign_document(signature_string)
        signed = self.build_signature(self.key_id, signature)
        self.__generate_sign_header(signed)

        headers = self.headers.copy()
        headers.pop("(request-target)")

        return headers
