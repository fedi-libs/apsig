import unittest
from cryptography.hazmat.primitives.asymmetric import ed25519

from apsig import OIPSigner, OIPVerifier

class TestOIPSignerVerifier(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.private_key = ed25519.Ed25519PrivateKey.generate()
        cls.public_key = cls.private_key.public_key()

        cls.publickey_url = "https://server.example/keys/test#ed25519-key"

    def test_sign_and_verify(self):
        json_object = {
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/data-integrity/v1"
            ],
            "id": "https://server.example/objects/1",
            "type": "Note",
            "attributedTo": "https://server.example/users/alice",
            "content": "Hello world"
        }

        signer = OIPSigner(self.private_key)
        signed_object = signer.sign(json_object, self.publickey_url)

        verifier = OIPVerifier(self.public_key)
        is_valid = verifier.verify(signed_object)

        self.assertTrue(is_valid)

    def test_verify_invalid_signature(self):
        json_object = {
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/data-integrity/v1"
            ],
            "id": "https://server.example/objects/1",
            "type": "Note",
            "attributedTo": "https://server.example/users/alice",
            "content": "Hello world"
        }

        signer = OIPSigner(self.private_key)
        signed_object = signer.sign(json_object, self.publickey_url)

        signed_object['proof']['proofValue'] = "00" # Falsified signatures

        verifier = OIPVerifier(self.public_key)
        is_valid = verifier.verify(signed_object)

        self.assertFalse(is_valid)

    def test_missing_proof(self):
        json_object = {
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/data-integrity/v1"
            ],
            "id": "https://server.example/objects/1",
            "type": "Note",
            "attributedTo": "https://server.example/users/alice",
            "content": "Hello world"
        }

        verifier = OIPVerifier(self.public_key)

        with self.assertRaises(ValueError) as context:
            verifier.verify(json_object)

        self.assertEqual(str(context.exception), "Proof not found in the object")

if __name__ == '__main__':
    unittest.main()
