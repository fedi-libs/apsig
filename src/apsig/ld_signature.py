import hashlib
import os
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .__polyfill.datetime import utcnow
from .exceptions import MissingSignature

class LDSignature:
    def __init__(self):
        pass

    def __normalize(self, data):
        if isinstance(data, dict):
            normalized = {k: self.__normalize(v) for k, v in sorted(data.items())}
        elif isinstance(data, list):
            normalized = [self.__normalize(item) for item in sorted(data)]
        else:
            normalized = data
        return normalized

    def __create_verify_data(self, data, options):
        transformed_options = {**options}
        transformed_options.pop("type", None)
        transformed_options.pop("id", None)
        transformed_options.pop("signatureValue", None)

        normalized_options = self.__normalize(transformed_options)
        options_hash = hashlib.sha256(json.dumps(normalized_options, sort_keys=True).encode("utf-8")).hexdigest()

        transformed_data = {**data}
        transformed_data.pop("signature", None)

        normalized_data = self.__normalize(transformed_data)
        document_hash = hashlib.sha256(json.dumps(normalized_data, sort_keys=True).encode("utf-8")).hexdigest()

        verify_data = f"{options_hash}{document_hash}"
        return verify_data

    def sign(self, data, creator, domain=None, created=None, private_key=None):
        options = {
            "type": "RsaSignature2017",
            "creator": creator,
            "domain": domain,
            "nonce": os.urandom(16).hex(),
            "created": created or utcnow().isoformat(),
        }
        if not domain:
            options.pop("domain", None)

        to_be_signed = self.__create_verify_data(data, options)

        signer = private_key.sign(
            to_be_signed.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
        )

        return {**data, "signature": {**options, "signatureValue": signer.hex()}}

    def verify(self, data, public_key):
        if data.get("signature") is None:
            raise MissingSignature
        to_be_signed = self.__create_verify_data(data, data["signature"])
        

        try:
            public_key.verify(
                bytes.fromhex(data["signature"]["signatureValue"]),
                to_be_signed.encode("utf-8"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    @staticmethod
    def generate_rsa_keypair():
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key