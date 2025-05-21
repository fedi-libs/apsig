import unittest
import email.utils

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from apsig.draft import Signer, Verifier
from apsig.exceptions import VerificationFailed, MissingSignature

class TestSignatureFunctions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        cls.public_key = cls.private_key.public_key()

        cls.public_pem = cls.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def test_create_and_verify_signature(self):
        date = email.utils.formatdate(usegmt=True)

        method = "POST"
        url = "https://example.com/api/resource"
        headers = {
            "Content-Type": "application/json",
            "Date": date,
        }
        body = '{"key": "value"}'

        signer = Signer(
            headers=headers,
            private_key=self.private_key,
            method=method,
            url=url,
            key_id="https://example.com/users/johndoe#main-key",
            body=body,
        )

        signed_headers = signer.sign()
        verifier = Verifier(
            public_pem=self.public_pem,
            method=method,
            url=url,
            headers=signed_headers,
            body=body.encode("utf-8"),
        )

        result = verifier.verify(raise_on_fail=True)

        self.assertIsInstance(result, str)
        self.assertEqual(result, "https://example.com/users/johndoe#main-key")

    def test_create_and_verify_signature_method_get(self):
        date = email.utils.formatdate(usegmt=True)

        method = "GET"
        url = "https://example.com/api/resource"
        headers = {
            "Content-Type": "application/json",
            "Date": date,
        }

        signer = Signer(
            headers=headers,
            private_key=self.private_key,
            method=method,
            url=url,
            key_id="https://example.com/users/johndoe#main-key",
        )

        signed_headers = signer.sign()
        verifier = Verifier(
            public_pem=self.public_pem,
            method=method,
            url=url,
            headers=signed_headers,
        )

        result = verifier.verify(raise_on_fail=True)

        self.assertIsInstance(result, str)
        self.assertEqual(result, "https://example.com/users/johndoe#main-key")

    def test_too_far_date(self):
        method = "POST"
        url = "https://example.com/api/resource"
        headers = {
            "Content-Type": "application/json",
            "Date": "Wed, 21 Oct 2015 07:28:00 GMT",
        }
        body = '{"key": "value"}'

        signer = Signer(
            headers=headers,
            private_key=self.private_key,
            method=method,
            url=url,
            key_id="https://example.com/users/johndoe#main-key",
            body=body,
        )

        signed_headers = signer.sign()
        verifier = Verifier(
            public_pem=self.public_pem,
            method=method,
            url=url,
            headers=signed_headers,
            body=body.encode("utf-8"),
        )

        with self.assertRaises(VerificationFailed, msg="Date header is too far from current time"):
            verifier.verify(raise_on_fail=True)

    def test_verify_invalid_signature(self):
        method = "POST"
        url = "https://example.com/api/resource"
        headers = {
            "Content-Type": "application/json",
            "Date": "Wed, 21 Oct 2015 07:28:00 GMT",
            "Signature": 'keyId="your-key-id",algorithm="rsa-sha256",headers="(request-target) Content-Type Date",signature="invalid_signature"',
        }
        body = '{"key": "value"}'

        verifier = Verifier(
            public_pem=self.public_pem,
            method=method,
            url=url,
            headers=headers,
            body=body.encode("utf-8"),
        )

        with self.assertRaises(VerificationFailed, msg="Invalid signature"):
            verifier.verify(raise_on_fail=True)

    def test_missing_signature_header(self):
        method = "POST"
        url = "https://example.com/api/resource"
        headers = {
            "Content-Type": "application/json",
            "Date": "Wed, 21 Oct 2015 07:28:00 GMT",
        }
        body = '{"key": "value"}'
        verifier = Verifier(
            public_pem=self.public_pem,
            method=method,
            url=url,
            headers=headers,
            body=body.encode("utf-8"),
        )

        with self.assertRaises(MissingSignature, msg="Signature header is missing"):
            verifier.verify(raise_on_fail=True)


if __name__ == "__main__":
    unittest.main()
