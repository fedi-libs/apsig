# This code was ported from Takahe.

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

    def verify(self, doc: dict, public_key: rsa.RSAPublicKey | str):
        if isinstance(public_key, str):
            codec, data = multicodec.unwrap(multibase.decode(public_key))
            if codec.name != "rsa-pub":
                raise ValueError("public_key must be RSA PublicKey.")
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
            raise MissingSignature("Invalid signature section")
        if signature["type"].lower() != "rsasignature2017":
            raise UnknownSignature("Unknown signature type")
        final_hash = self.__normalized_hash(options) + self.__normalized_hash(document)
        try:
            public_key.verify(
                base64.b64decode(signature["signatureValue"]),
                final_hash,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except InvalidSignature:
            raise VerificationFailed("LDSignature mismatch")


"""
if __name__ == "__main__":
    # RSA鍵ペアを生成
    private_key, public_key = LDSignature.generate_rsa_keypair()

    # ドキュメントの例
    document = {
        "actor": "http://example.com/alice",
        "signature": {}
    }

    # 署名の生成
    ld_signature = LDSignature()
    ld_signature.sign(document, private_key)
    print("Generated Document with Signature:")
    print(json.dumps(document, indent=2))

    # 署名の検証
    is_valid = ld_signature.verify(document, public_key)
    print("Is the signature valid?", is_valid)
"""
