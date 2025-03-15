# This code was ported from Takahe.

from typing import Union
import datetime
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from pyld import jsonld
from cryptography.exceptions import InvalidSignature

from .__polyfill.datetime import utcnow
from multiformats import multibase, multicodec
from .exceptions import MissingSignature, UnknownSignature, VerificationFailed

class LDSignature:
    """A class for signing and verifying Linked Data signatures using the RSA signature algorithm. 

    Attributes:
        private_key (rsa.RSAPrivateKey): The RSA private key used for signing.
        public_key (rsa.RSAPublicKey): The corresponding RSA public key.

    Methods:
        sign(doc: dict, creator: str, private_key: rsa.RSAPrivateKey, options: dict = None, created: datetime.datetime = None) -> dict:
            Signs the provided document using the specified RSA private key.

        verify(doc: dict, public_key: rsa.RSAPublicKey | str) -> bool:
            Verifies the signature of the provided document against the given public key.
    """

    def __init__(self):
        pass

    def __normalized_hash(self, data):
        norm_form = jsonld.normalize(
            data, {"algorithm": "URDNA2015", "format": "application/n-quads"}
        )
        digest = hashes.Hash(hashes.SHA256())
        digest.update(norm_form.encode("utf8"))
        return digest.finalize().hex().encode("ascii")

    def sign(
        self,
        doc: dict,
        creator: str,
        private_key: rsa.RSAPrivateKey,
        options: dict = None,
        created: datetime.datetime = None,
    ):
        """Signs the provided document using the specified RSA private key.

        Args:
            doc (dict): The document to be signed.
            creator (str): The identifier of the creator of the document.
            private_key (rsa.RSAPrivateKey): The RSA private key used for signing.
            options (dict, optional): Additional signing options. Defaults to None.
            created (datetime.datetime, optional): The timestamp when the signature is created. 
                Defaults to the current UTC time if not provided.

        Returns:
            dict: The signed document containing the original data and the signature.
        """
        options: dict[str, str] = {
            "@context": "https://w3c-ccg.github.io/security-vocab/contexts/security-v1.jsonld", # "https://w3id.org/identity/v1"
            "creator": creator,
            "created": created or utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        }

        to_be_signed = self.__normalized_hash(options) + self.__normalized_hash(doc)

        signature = base64.b64encode(private_key.sign(
            to_be_signed, padding.PKCS1v15(), hashes.SHA256()
        ))

        return {
            **doc,
            "signature": {
                **options,
                "type": "RsaSignature2017",
                "signatureValue": signature.decode("ascii"),
            },
        }

    def verify(self, doc: dict, public_key: rsa.RSAPublicKey | str, raise_on_fail: bool = False) -> Union[str, None]:
        """Verifies the signature of the provided document against the given public key.

        Args:
            doc (dict): The signed document to verify.
            public_key (rsa.RSAPublicKey | str): The RSA public key in PEM format or as a multibase-encoded string.

        Returns:
            bool: True if the signature is valid; otherwise, an exception is raised.

        Raises:
            MissingSignature: If the signature section is missing in the document.
            UnknownSignature: If the signature type is not recognized.
            VerificationFailed: If the signature verification fails.
        """
        if isinstance(public_key, str):
            codec, data = multicodec.unwrap(multibase.decode(public_key))
            if codec.name != "rsa-pub":
                if raise_on_fail:
                    raise ValueError("public_key must be RSA PublicKey.")
                return None
            public_key = serialization.load_pem_public_key(data, backend=default_backend())
        try:
            document = doc.copy()
            signature = document.pop("signature")
            options = {
                "@context": "https://w3c-ccg.github.io/security-vocab/contexts/security-v1.jsonld",
                "creator": signature["creator"],
                "created": signature["created"],
            }
        except KeyError:
            if raise_on_fail:
                raise MissingSignature("Invalid signature section")
            return None
        if signature["type"].lower() != "rsasignature2017":
            if raise_on_fail:
                raise UnknownSignature("Unknown signature type")
            return None
        final_hash = self.__normalized_hash(options) + self.__normalized_hash(document)
        try:
            public_key.verify(
                base64.b64decode(signature["signatureValue"]),
                final_hash,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return signature["creator"]
        except InvalidSignature:
            if raise_on_fail:
                raise VerificationFailed("LDSignature mismatch")
            return None