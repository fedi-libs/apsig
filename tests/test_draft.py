import unittest

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from apsig import draftSigner, draftVerifier

class TestSignatureFunctions(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        cls.public_key = cls.private_key.public_key()

        cls.public_pem = cls.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    def test_create_and_verify_signature(self):
        method = "POST"
        url = "https://example.com/api/resource"
        headers = {
            "Content-Type": "application/json",
            "Date": "Wed, 21 Oct 2015 07:28:00 GMT"
        }
        body = '{"key": "value"}'

        signed_headers = draftSigner.sign(self.private_key, method, url, headers, "https://example.com/users/johndoe#main-key", body)

        is_valid, message = draftVerifier.verify(public_pem=self.public_pem, method=method, url=url, headers=signed_headers, body=body.encode("utf-8"))

        self.assertTrue(is_valid)
        self.assertEqual(message, "Signature is valid")

    def test_verify_invalid_signature(self):
        method = "POST"
        url = "https://example.com/api/resource"
        headers = {
            "Content-Type": "application/json",
            "Date": "Wed, 21 Oct 2015 07:28:00 GMT",
            "Signature": 'keyId="your-key-id",algorithm="rsa-sha256",headers="(request-target) Content-Type Date",signature="invalid_signature"'
        }
        body = '{"key": "value"}'

        is_valid, message = draftVerifier.verify(self.public_pem, method, url, headers, body.encode("utf-8"))

        self.assertFalse(is_valid)
        self.assertEqual(message, "Invalid signature")

    def test_missing_signature_header(self):
        method = "POST"
        url = "https://example.com/api/resource"
        headers = {
            "Content-Type": "application/json",
            "Date": "Wed, 21 Oct 2015 07:28:00 GMT"
        }
        body = '{"key": "value"}'

        is_valid, message = draftVerifier.verify(self.public_pem, method, url, headers, body.encode("utf-8"))

        self.assertFalse(is_valid)
        self.assertEqual(message, "Signature header is missing")

if __name__ == '__main__':
    unittest.main()
