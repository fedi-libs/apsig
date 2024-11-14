import json
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

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
        proof_value = bytes.fromhex(proof['proofValue'])
        
        proofless_object = json_object.copy()
        del proofless_object['proof']
        
        canonical_data = self.canonicalize(proofless_object)
        data_hash = self.hash_data(canonical_data)

        return self.verify_signature(proof_value, data_hash)

def load_public_key(pem_data):
    """PEM形式の公開鍵を読み込む"""
    return serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )

def main():
    # 公開鍵の読み込み（例としてPEMファイルから）
    with open("public_key.pem", "rb") as key_file:
        public_key = load_public_key(key_file.read())

    verifier = OIPVerifier(public_key)

    # サンプルの署名付きJSONオブジェクト
    signed_object = {
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/data-integrity/v1"
        ],
        "id": "https://server.example/objects/1",
        "type": "Note",
        "attributedTo": "https://server.example/users/alice",
        "content": "Hello world",
        "proof": {
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/data-integrity/v1"
            ],
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": "https://server.example/users/alice#ed25519-key",
            "proofPurpose": "assertionMethod",
            "proofValue": "署名の16進数文字列",  # ここは実際の署名に置き換えてください
            "created": "2023-02-24T23:36:38Z"
        }
    }

    # 署名の検証
    is_valid = verifier.verify_proof(signed_object)
    if is_valid:
        print("証明書は有効です。")
    else:
        print("証明書は無効です。")

if __name__ == "__main__":
    main()
