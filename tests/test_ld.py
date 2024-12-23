import unittest

from apsig import LDSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from apsig.exceptions import MissingSignature

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
        is_valid = self.ld.verify(self.signed_data, self.public_key)
        self.assertTrue(is_valid)

    def test_verify_invalid_signature_value(self):
        signed_data = self.ld.sign(self.data, "https://example.com/users/johndoe#main-key", private_key=self.private_key)
        signed_data["signature"]["signatureValue"] = "invalid_signature"
        is_valid = self.ld.verify(signed_data, self.public_key)
        self.assertFalse(is_valid)
        
    def test_verify_missing_signature(self):
        try:
            self.ld.verify(self.data, self.public_key)
            is_fail = False
        except MissingSignature:
            is_fail = True
        self.assertTrue(is_fail)
        
    def test_verify_invalid_signature(self):
        signed_data = self.ld.sign(self.data, "https://example.com/users/johndoe#main-key", private_key=self.private_key)
        signed_data["signature"]["type"] = "RsaSignatureHoge"
        is_fail = self.ld.verify(signed_data, self.public_key)
        self.assertTrue(is_fail)

if __name__ == '__main__':
    unittest.main()
