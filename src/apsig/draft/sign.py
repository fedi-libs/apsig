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
    def __init__(self, headers: dict[Any, Any], private_key: rsa.RSAPrivateKey, method: str, url: str, key_id: str, body: bytes | dict=b"", signed_headers: list[str] | None = None) -> None:
        """Signs an HTTP request with a digital signature.

        Args:
            private_key (rsa.RSAPrivateKey): The RSA private key used to sign the request.
            method (str): The HTTP method (e.g., "GET", "POST").
            url (str): The URL of the request.
            headers (dict): A dictionary of HTTP headers that will be signed.
            key_id (str): The key identifier to include in the signature header.
            body (bytes, optional): The request body. Defaults to an empty byte string.
            signed_headers (list[str], optional): A list of headers to include in the signature. Defaults to a secure set of headers.

        Raises:
            ValueError: If the signing process fails due to invalid parameters.
        """
        self.private_key = private_key
        self.method = method
        self.url = url
        self.key_id = key_id
        if isinstance(body, dict):
            self.body = json.dumps(body).encode("utf-8")
        else:
            self.body = body

        self.raw_headers = {str(k).lower(): v for k, v in headers.items()}

        if "date" not in self.raw_headers:
            self.raw_headers["date"] = email.utils.formatdate(usegmt=True)
        
        self.parsed_url: ParseResult = urlparse(url)
        if "host" not in self.raw_headers:
            self.raw_headers["host"] = self.parsed_url.netloc

        self.request_target = f"{method.lower()} {self.parsed_url.path}"

        if method.upper() != "GET":
            if "digest" not in self.raw_headers:
                self.raw_headers["digest"] = calculate_digest(self.body)

        if signed_headers:
            self.signed_headers = [h.lower() for h in signed_headers]
            if "(request-target)" not in self.signed_headers:
                self.signed_headers.insert(0, "(request-target)")
        else:
            default_headers = ["(request-target)", "date", "host"]
            if method.upper() != "GET":
                default_headers.append("digest")
            self.signed_headers = default_headers

    def __generate_sign_header(self, signature: str, headers: dict) -> dict:
        headers["Signature"] = signature
        headers["Authorization"] = f"Signature {signature}"
        return headers

    def __sign_document(self, document: bytes):
        return base64.standard_b64encode(self.private_key.sign(document, padding.PKCS1v15(), hashes.SHA256())).decode("utf-8")

    
    
    def build_signature(self, key_id: str, signature: str, algorithm: str = "rsa-sha256"):
        if algorithm != "rsa-sha256":
            raise NotImplementedError(f"Unsuppored algorithm: {algorithm}")
        
        return ",".join([
            f'keyId="{key_id}"',
            f'algorithm="{algorithm}"',
            f'headers="{" ".join(self.signed_headers)}"',
            f'signature="{signature}"'
        ])

    def sign(self) -> dict:
        signing_string_dict = {**self.raw_headers, "(request-target)": self.request_target}
        
        for header in self.signed_headers:
            if header not in signing_string_dict:
                raise ValueError(f"Header '{header}' specified in signed_headers is not in the request headers.")

        signature_string = build_string(signing_string_dict, headers=self.signed_headers).encode("utf-8")
        
        signature = self.__sign_document(signature_string)
        signed = self.build_signature(self.key_id, signature)

        final_headers = self.raw_headers.copy()
        final_headers = self.__generate_sign_header(signed, final_headers)

        return final_headers
