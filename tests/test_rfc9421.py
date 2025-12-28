import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from apsig.exceptions import MissingSignature, VerificationFailed
from apsig.rfc9421 import RFC9421Signer, RFC9421Verifier

private_key_rsa = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key_rsa = private_key_rsa.public_key()
KEY_ID_RSA = "test-key-rsa-v1_5-sha256"


def test_sign_and_verify_success():
    """
    Tests successful signing and verification of a request using RSA.
    """
    signer = RFC9421Signer(private_key_rsa, KEY_ID_RSA)
    method = "POST"
    path = "/foo"
    host = "example.com"
    headers = {
        "Content-Type": "application/json",
    }
    body = {"hello": "world"}

    signed_headers = signer.sign(method, path, host, headers, body)

    verifier = RFC9421Verifier(
        public_key_rsa,
        method,
        path,
        host,
        signed_headers,
    )

    verified_key_id = verifier.verify(raise_on_fail=True)
    assert verified_key_id == KEY_ID_RSA


def test_verification_fail_on_wrong_key():
    """
    Tests that verification fails when using the wrong public key.
    """
    signer = RFC9421Signer(private_key_rsa, KEY_ID_RSA)
    method = "POST"
    path = "/foo"
    host = "example.com"
    headers = {
        "Content-Type": "application/json",
    }
    body = {"hello": "world"}

    signed_headers = signer.sign(method, path, host, headers, body)

    wrong_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    wrong_public_key = wrong_private_key.public_key()

    verifier = RFC9421Verifier(
        wrong_public_key,
        method,
        path,
        host,
        signed_headers,
    )

    with pytest.raises(VerificationFailed):
        verifier.verify(raise_on_fail=True)


def test_verification_fail_on_tampered_header():
    """
    Tests that verification fails if a signed header is tampered with.
    """
    signer = RFC9421Signer(private_key_rsa, KEY_ID_RSA)
    method = "POST"
    path = "/foo"
    host = "example.com"
    headers = {
        "Content-Type": "application/json",
    }
    body = {"hello": "world"}

    signed_headers = signer.sign(method, path, host, headers, body)

    signed_headers["date"] = "this is not a date"

    verifier = RFC9421Verifier(
        public_key_rsa,
        method,
        path,
        host,
        signed_headers,
    )

    with pytest.raises(VerificationFailed):
        verifier.verify(raise_on_fail=True)


def test_missing_signature_header():
    """
    Tests that verification fails if the Signature header is missing.
    """
    method = "POST"
    path = "/foo"
    host = "example.com"
    headers = {
        "Content-Type": "application/json",
        "date": "some date",
        "content-length": "10",
        "signature-input": "sig1=();created=123",
    }

    verifier = RFC9421Verifier(
        public_key_rsa,
        method,
        path,
        host,
        headers,
    )

    with pytest.raises(MissingSignature):
        verifier.verify(raise_on_fail=True)

    assert verifier.verify() is None


def test_missing_signature_input_header():
    """
    Tests that verification fails if the Signature-Input header is missing.
    """
    method = "POST"
    path = "/foo"
    host = "example.com"
    headers = {
        "Content-Type": "application/json",
        "date": "some date",
        "content-length": "10",
        "signature": "sig1=:...",
    }

    verifier = RFC9421Verifier(
        public_key_rsa,
        method,
        path,
        host,
        headers,
    )

    with pytest.raises(MissingSignature):
        verifier.verify(raise_on_fail=True)

    assert verifier.verify() is None