from typing import Union
import base64
from urllib.parse import urlparse
import json

import pytz
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pyfill import datetime
from typing_extensions import deprecated

from .tools import build_string, calculate_digest
from ..exceptions import MissingSignature, UnknownSignature, VerificationFailed


class draftVerifier:
    @staticmethod
    @deprecated(
        "apsig.draft.verify.draftVerifier is deprecated; use apsig.draft.verify.Verifier instead. This will be removed in apsig 1.0."
    )
    def verify(
        public_pem: str, method: str, url: str, headers: dict, body: bytes = None
    ) -> tuple[bool, str]:
        """Verifies the digital signature of an HTTP request.

        Args:
            public_pem (str): The public key in PEM format used to verify the signature.
            method (str): The HTTP method (e.g., "GET", "POST").
            url (str): The URL of the request.
            headers (dict): A dictionary of HTTP headers, including the signature and other relevant information.
            body (bytes, optional): The request body. Defaults to an empty byte string.

        Returns:
            tuple: A tuple containing:
                - bool: True if the signature is valid, False otherwise.
                - str: A message indicating the result of the verification.

        Raises:
            ValueError: If the signature header is missing or if the algorithm is unsupported.
        """
        try:
            result = Verifier(
                public_pem=public_pem, method=method, url=url, headers=headers, body=body
            ).verify(raise_on_fail=True)
        except Exception as e:
            return False, str(e)
        if result:
            return True, "Signature is valid"


class Verifier:
    def __init__(
        self, public_pem: Union[rsa.RSAPublicKey, str], method: str, url: str, headers: dict, body: bytes | dict = None
    ) -> None:
        """
        Args:
            public_pem (str): The public key in PEM format used to verify the signature.
            method (str): The HTTP method (e.g., "GET", "POST").
            url (str): The URL of the request.
            headers (dict): A dictionary of HTTP headers, including the signature and other relevant information.
            body (bytes, optional): The request body. Defaults to an empty byte string.
        """
        if isinstance(public_pem, str) or isinstance(public_pem, bytes):
            self.public_key = serialization.load_pem_public_key(
                public_pem.encode("utf-8") if isinstance(public_pem, str) else public_pem, backend=default_backend()
            )
        else:
            self.public_key = public_pem
        self.method = method
        self.url = url
        self.headers_raw = headers
        self.headers = {key.lower(): value for key, value in headers.items()}
        if isinstance(body, dict):
            self.body = json.dumps(body, separators=(',', ':')).encode("utf-8")
        else:
            self.body = body

    def __decode_sign(self, signature):
        return base64.standard_b64decode(signature)

    def verify(self, raise_on_fail: bool = False) -> Union[str, None]:
        """Verifies the digital signature of an HTTP request.

        Args:
            raise_on_fail (bool, optional): Return error on failure. defaults to False.

        Returns:

        Raises:
            ValueError: If the signature header is missing or if the algorithm is unsupported.
        """
        headers = self.headers.copy()

        signature_header = headers.get("signature")
        if not signature_header:
            if raise_on_fail:
                raise MissingSignature(
                    "Signature header is missing"
                )
            return None

        signature_parts = {}
        for item in signature_header.split(","):
            key, value = item.split("=", 1)
            signature_parts[key.strip()] = value.strip().strip('"')

        signature = self.__decode_sign(signature_parts["signature"])
        key_id = signature_parts["keyId"]
        algorithm = signature_parts["algorithm"]

        if algorithm != "rsa-sha256":
            if raise_on_fail:
                raise UnknownSignature(
                    f"Unsupported algorithm. Algorithm must be rsa-sha256, but passed {algorithm}."
                )
            return None

        signed_headers = signature_parts["headers"].split()

        parsed_url = urlparse(self.url)

        signature_headers = headers.copy()
        signature_headers["(request-target)"] = (
            f"{self.method.lower()} {parsed_url.path}"
        )
        signature_string = build_string(
            signature_headers, headers=signed_headers
        ).encode("utf-8")

        try:
            self.public_key.verify(
                signature, signature_string, padding.PKCS1v15(), hashes.SHA256()
            )
        except InvalidSignature:
            if raise_on_fail:
                raise VerificationFailed(
                    "Invalid signature"
                )
            return None

        if self.body:
            expected_digest = calculate_digest(self.body)
            if headers.get("digest") != expected_digest:
                if raise_on_fail:
                    raise VerificationFailed(
                        "Digest mismatch"
                    )
                return None

        date_header = headers.get("date")
        if date_header:
            date = datetime.datetime.datetime.strptime(
                date_header, "%a, %d %b %Y %H:%M:%S GMT"
            )
            gmt_tz = pytz.timezone('GMT')
            gmt_time = gmt_tz.localize(date)
            request_time = gmt_time.astimezone(pytz.utc)
            current_time = datetime.utcnow()
            if abs((current_time - request_time).total_seconds()) > 3600:
                if raise_on_fail:
                    raise VerificationFailed(
                        "Date header is too far from current time"
                    )
                return None

        return key_id
