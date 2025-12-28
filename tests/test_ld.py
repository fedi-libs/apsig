import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from apsig import LDSignature
from apsig.exceptions import (
    MissingSignature,
    UnknownSignature,
    VerificationFailed,
)


@pytest.fixture(scope="module")
def setup_data():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    ld = LDSignature()

    data = {
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
        ],
        "type": "Note",
        "content": "Hello, world!",
    }

    key_id = "https://example.com/users/johndoe#main-key"
    signed_data = ld.sign(data, key_id, private_key=private_key)

    return {
        "private_key": private_key,
        "public_key": public_key,
        "ld": ld,
        "data": data,
        "signed_data": signed_data,
        "key_id": key_id
    }

def test_sign_and_verify(setup_data):
    d = setup_data
    result = d["ld"].verify(
        d["signed_data"], d["public_key"], raise_on_fail=True
    )

    assert isinstance(result, str)
    assert result == d["key_id"]


def test_verify_invalid_signature_value(setup_data):
    d = setup_data
    d["signed_data"]["signature"]["signatureValue"] = "invalid_signature"

    with pytest.raises(VerificationFailed):
        d["ld"].verify(d["signed_data"], d["public_key"], raise_on_fail=True)


def test_verify_missing_signature(setup_data):
    d = setup_data

    with pytest.raises(MissingSignature):
        d["ld"].verify(d["data"], d["public_key"], raise_on_fail=True)


def test_verify_invalid_signature_type(setup_data):
    d = setup_data

    d["signed_data"]["signature"]["type"] = "RsaSignatureHoge"

    with pytest.raises(UnknownSignature):
        d["ld"].verify(d["signed_data"], d["public_key"], raise_on_fail=True)