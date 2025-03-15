import unittest

from apsig import LDSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from apsig.exceptions import MissingSignature, VerificationFailed, UnknownSignature

class TestJsonLdSigner(unittest.TestCase):
    def setUp(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.ld = LDSignature()
        self.data = {
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/v1",
            ],
            "type": "Note",
            "content": "Hello, world!"
        }
        self.signed_data = self.ld.sign(self.data, "https://example.com/users/johndoe#main-key", private_key=self.private_key)

    def test_sign_and_verify(self):
        result = self.ld.verify(self.signed_data, self.public_key, raise_on_fail=True)
        self.assertIsInstance(result, str)
        self.assertEqual(result, "https://example.com/users/johndoe#main-key")

    def test_verify_invalid_signature_value(self):
        signed_data = self.ld.sign(self.data, "https://example.com/users/johndoe#main-key", private_key=self.private_key)
        signed_data["signature"]["signatureValue"] = "invalid_signature"
        with self.assertRaises(VerificationFailed, msg="LDSignature mismatch"):
            self.ld.verify(signed_data, self.public_key, raise_on_fail=True)
        
    def test_verify_missing_signature(self):
        with self.assertRaises(MissingSignature, msg="Invalid signature section"):
            self.ld.verify(self.data, self.public_key, raise_on_fail=True)
        
    def test_verify_invalid_signature(self):
        signed_data = self.ld.sign(self.data, "https://example.com/users/johndoe#main-key", private_key=self.private_key)
        signed_data["signature"]["type"] = "RsaSignatureHoge"
        with self.assertRaises(UnknownSignature, msg="Unknown signature type"):
            self.ld.verify(signed_data, self.public_key, raise_on_fail=True)

if __name__ == '__main__':
    unittest.main()
