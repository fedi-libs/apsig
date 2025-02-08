import json
import hashlib

from multiformats import multibase

class OIPVerifier:
    def __init__(self, public_key):
        self.public_key = public_key

    def canonicalize(self, data: dict) -> bytes:
        return json.dumps(data, sort_keys=True).encode('utf-8')

    def hash_data(self, canonical_data: bytes) -> bytes:
        return hashlib.sha256(canonical_data).digest()

    def verify_signature(self, signature: bytes, data_hash: bytes) -> bool:
        try:
            self.public_key.verify(signature, data_hash)
            return True
        except Exception:
            return False

    def verify(self, json_object: dict) -> bool:
        if 'proof' not in json_object:
            raise ValueError("Proof not found in the object")

        proof = json_object['proof']
        proof_value = multibase.decode(proof['proofValue'])
        
        proofless_object = json_object.copy()
        del proofless_object['proof']
        
        canonical_data = self.canonicalize(proofless_object)
        data_hash = self.hash_data(canonical_data)

        return self.verify_signature(proof_value, data_hash)