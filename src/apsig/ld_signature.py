import hashlib
import json
import datetime
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from .__polyfill.datetime import utcnow


class LDSignature:
    def __init__(self):
        pass

    def _options_hash(self, doc):
        doc = dict(doc["signature"])
        for k in ["type", "id", "signatureValue"]:
            doc.pop(k, None)
        doc["@context"] = "https://w3id.org/identity/v1"

        normalized = json.dumps(doc, sort_keys=True)
        h = hashlib.sha256()
        h.update(normalized.encode("utf-8"))
        return h.hexdigest()

    def _doc_hash(self, doc):
        doc = dict(doc)
        doc.pop("signature", None)

        normalized = json.dumps(doc, sort_keys=True)
        h = hashlib.sha256()
        h.update(normalized.encode("utf-8"))
        return h.hexdigest()

    def sign(
        self,
        doc: dict,
        creator: str,
        private_key: rsa.RSAPrivateKey,
        options: dict = None,
        created: datetime.datetime = None,
        domain: str = None
    ):
        options = {
            'type': 'RsaSignature2017',
            'creator': creator,
            'nonce': os.urandom(16).hex(),
            'created': (created or utcnow().replace(microsecond=0)).isoformat() + "Z"
        }
        if domain:
            options['domain'] = domain
        to_be_signed = json.dumps({**doc, **options}, sort_keys=True)
        signature = private_key.sign(
            to_be_signed.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return {
            **doc,
            "signature": {
                **options,
                "signatureValue": base64.b64encode(signature).decode('utf-8')
            }
        }

    def verify(self, doc, public_key):
        to_be_signed = self._options_hash(doc) + self._doc_hash(doc)
        signature = doc["signature"]["signatureValue"]
        signature_bytes = base64.b64decode(signature)

        try:
            public_key.verify(
                signature_bytes,
                to_be_signed.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False


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
