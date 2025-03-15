import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519

from apsig import ProofSigner, ProofVerifier
from multiformats import multibase, multicodec


class TestProofSignerVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = ed25519.Ed25519PrivateKey.generate()
        cls.public_key = cls.private_key.public_key()
        cls.private_key_multibase = multibase.encode((multicodec.wrap("ed25519-priv", cls.private_key.private_bytes_raw())), base="base58btc")
        cls.public_key_multibase = multibase.encode((multicodec.wrap("ed25519-pub", cls.public_key.public_bytes_raw())), base="base58btc")
        cls.time = "2024-01-01T09:00:00Z"
        cls.publickey_url = "https://server.example/keys/test#ed25519-key"

    def test_sign_and_verify(self):
        json_object = {
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/data-integrity/v1",
            ],
            "id": "https://server.example/objects/1",
            "type": "Note",
            "attributedTo": "https://server.example/users/alice",
            "content": "Hello world",
        }

        signer = ProofSigner(self.private_key)
        signed_object = signer.sign(json_object, {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": "https://example.com/keys/1",
            "created": self.time,
        })

        verifier = ProofVerifier(self.public_key)
        result = verifier.verify(signed_object)

        self.assertIsInstance(result, str)
        self.assertEqual(result, "https://example.com/keys/1")

    def test_verify_invalid_signature(self):
        json_object = {
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/data-integrity/v1",
            ],
            "id": "https://server.example/objects/1",
            "type": "Note",
            "attributedTo": "https://server.example/users/alice",
            "content": "Hello world",
        }

        signer = ProofSigner(self.private_key)
        signed_object = signer.sign(json_object, {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": "https://example.com/keys/1",
            "created": self.time,
        })

        signed_object["proof"]["proofValue"] = (
            "zLaewdp4H9kqtwyrLatK4cjY5oRHwVcw4gibPSUDYDMhi4M49v8pcYk3ZB6D69dNpAPbUmY8ocuJ3m9KhKJEEg7z"  # Dummy Text
        )

        verifier = ProofVerifier(self.public_key)
        result = verifier.verify(signed_object)

        self.assertIsNone(result)

    def test_missing_proof(self):
        json_object = {
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/data-integrity/v1",
            ],
            "id": "https://server.example/objects/1",
            "type": "Note",
            "attributedTo": "https://server.example/users/alice",
            "content": "Hello world",
        }

        verifier = ProofVerifier(self.public_key)

        with self.assertRaises(ValueError, msg="Proof not found in the object"):
            verifier.verify(json_object, raise_on_fail=True)


if __name__ == "__main__":
    unittest.main()
