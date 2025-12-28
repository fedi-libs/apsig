import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from apsig import ProofSigner, ProofVerifier


@pytest.fixture(scope="module")
def test_env():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    return {
        "private_key": private_key,
        "public_key": public_key,
        "time": "2024-01-01T09:00:00Z",
        "verification_method": "https://example.com/keys/1",
    }


@pytest.fixture
def base_json():
    return {
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/data-integrity/v1",
        ],
        "id": "https://server.example/objects/1",
        "type": "Note",
        "attributedTo": "https://server.example/users/alice",
        "content": "Hello world",
    }


def test_sign_and_verify(test_env, base_json):
    signer = ProofSigner(test_env["private_key"])
    signed_object = signer.sign(
        base_json,
        {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": test_env["verification_method"],
            "created": test_env["time"],
        },
    )

    verifier = ProofVerifier(test_env["public_key"])
    result = verifier.verify(signed_object)

    assert isinstance(result, str)
    assert result == test_env["verification_method"]


def test_verify_invalid_signature(test_env, base_json):
    signer = ProofSigner(test_env["private_key"])
    signed_object = signer.sign(
        base_json,
        {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": test_env["verification_method"],
            "created": test_env["time"],
        },
    )

    signed_object["proof"]["proofValue"] = (
        "zLaewdp4H9kqtwyrLatK4cjY5oRHwVcw4gibPSUDYDMhi4M49v8pcYk3ZB6D69dNpAPbUmY8ocuJ3m9KhKJEEg7z"
    )

    verifier = ProofVerifier(test_env["public_key"])
    result = verifier.verify(signed_object)

    assert result is None


def test_missing_proof(test_env, base_json):
    verifier = ProofVerifier(test_env["public_key"])

    with pytest.raises(ValueError):
        verifier.verify(base_json, raise_on_fail=True)
