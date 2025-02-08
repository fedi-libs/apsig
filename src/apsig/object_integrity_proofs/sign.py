import json
import hashlib

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from multiformats import multibase

from ..__polyfill.datetime import utcnow

class OIPSigner:
    def __init__(self, private_key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey):
        self.private_key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey = private_key

    def calculate_message_digest(self, data: dict) -> bytes:
        return hashlib.sha256(json.dumps(json.loads(json.dumps(data)), separators=(',', ':')).encode("utf-8")).digest()

    def calculate_proof_digest(self, proof_config: dict) -> bytes:
        proof_canon = json.dumps(proof_config, separators=(',', ':'))
        proof_bytes = proof_canon.encode('utf-8')
        return hashlib.sha256(proof_bytes).digest()

    def sign_hash(self, data_hash: bytes) -> bytes:
        return self.private_key.sign(data_hash)

    def sign(self, json_object: dict, publickey_url: str, created=None, context: list | str="https://w3id.org/security/data-integrity/v1"):
        if not isinstance(self.private_key, ed25519.Ed25519PrivateKey):
            raise TypeError("Unsupported algorithm")

        msg_digest = self.calculate_message_digest(json_object)
        created = created or utcnow().isoformat() #+ "Z"
        proof_config = {
            "@context": context or "https://w3id.org/security/data-integrity/v1",
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": publickey_url,
            "proofPurpose": "assertionMethod",
            "created": created,
        }
        proof_digest = self.calculate_proof_digest(proof_config)

        digest = proof_digest + msg_digest
        sig = self.private_key.sign(digest)
        proof_config["proofValue"] = multibase.encode(sig.hex().encode("utf-8"), "base58btc")
        json_object["proof"] = proof_config
        return json_object
