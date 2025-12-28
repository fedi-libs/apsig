import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from apsig import KeyUtil


@pytest.fixture(scope="module")
def kutil():
    private_key = ed25519.Ed25519PrivateKey.generate()
    return KeyUtil(private_key=private_key)


def test_encode(kutil):
    result = kutil.encode_multibase()

    assert result, "Encoding failed: result is empty or None"


def test_decode(kutil):
    multibase = kutil.encode_multibase()
    result = kutil.decode_multibase(multibase)

    assert result, "Decoding failed: result is empty or None"
