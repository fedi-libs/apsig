import email.utils

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from apsig.draft import Signer, Verifier
from apsig.exceptions import MissingSignature, VerificationFailed


@pytest.fixture(scope="module")
def keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return {"private": private_key, "public_pem": public_pem}

def test_create_and_verify_signature(keys):
    date = email.utils.formatdate(usegmt=True)
    method = "POST"
    url = "https://example.com/api/resource"
    headers = {
        "Content-Type": "application/json",
        "Date": date,
    }
    body = b'{"key": "value"}'

    signer = Signer(
        headers=headers,
        private_key=keys["private"],
        method=method,
        url=url,
        key_id="https://example.com/users/johndoe#main-key",
        body=body,
    )

    signed_headers = signer.sign()
    verifier = Verifier(
        public_pem=keys["public_pem"],
        method=method,
        url=url,
        headers=signed_headers,
        body=body,
    )

    result = verifier.verify(raise_on_fail=True)

    assert isinstance(result, str)
    assert result == "https://example.com/users/johndoe#main-key"


def test_create_and_verify_signature_method_get(keys):
    date = email.utils.formatdate(usegmt=True)
    method = "GET"
    url = "https://example.com/api/resource"
    headers = {
        "Content-Type": "application/json",
        "Date": date,
    }

    signer = Signer(
        headers=headers,
        private_key=keys["private"],
        method=method,
        url=url,
        key_id="https://example.com/users/johndoe#main-key",
    )

    signed_headers = signer.sign()
    verifier = Verifier(
        public_pem=keys["public_pem"],
        method=method,
        url=url,
        headers=signed_headers,
    )

    result = verifier.verify(raise_on_fail=True)

    assert isinstance(result, str)
    assert result == "https://example.com/users/johndoe#main-key"


def test_too_far_date(keys):
    method = "POST"
    url = "https://example.com/api/resource"
    headers = {
        "Content-Type": "application/json",
        "Date": "Wed, 21 Oct 2015 07:28:00 GMT",
    }
    body = b'{"key": "value"}'

    signer = Signer(
        headers=headers,
        private_key=keys["private"],
        method=method,
        url=url,
        key_id="https://example.com/users/johndoe#main-key",
        body=body,
    )

    signed_headers = signer.sign()
    verifier = Verifier(
        public_pem=keys["public_pem"],
        method=method,
        url=url,
        headers=signed_headers,
        body=body,
    )

    with pytest.raises(VerificationFailed):
        verifier.verify(raise_on_fail=True)


def test_verify_invalid_signature(keys):
    method = "POST"
    url = "https://example.com/api/resource"
    headers = {
        "Content-Type": "application/json",
        "Date": "Wed, 21 Oct 2015 07:28:00 GMT",
        "Signature": 'keyId="your-key-id",algorithm="rsa-sha256",headers="(request-target) Content-Type Date",signature="invalid_signature"',
    }
    body = b'{"key": "value"}'

    verifier = Verifier(
        public_pem=keys["public_pem"],
        method=method,
        url=url,
        headers=headers,
        body=body,
    )

    with pytest.raises(VerificationFailed):
        verifier.verify(raise_on_fail=True)


def test_missing_signature_header(keys):
    method = "POST"
    url = "https://example.com/api/resource"
    headers = {
        "Content-Type": "application/json",
        "Date": "Wed, 21 Oct 2015 07:28:00 GMT",
    }
    body = b'{"key": "value"}'

    verifier = Verifier(
        public_pem=keys["public_pem"],
        method=method,
        url=url,
        headers=headers,
        body=body,
    )

    with pytest.raises(MissingSignature):
        verifier.verify(raise_on_fail=True)
