# `apsig.LDSignature`
## Overview
The `LDSignature` class provides methods for signing and verifying Linked Data signatures 1.0 using RSA keys. It utilizes the W3C's security vocabulary and JSON-LD normalization to ensure the integrity and authenticity of the signed documents.

### Methods

#### `__init__(self)`
Initializes an instance of the `LDSignature` class.

#### `__normalized_hash(self, data: dict) -> bytes`
Generates a normalized hash of the given data.

**Args:**
- `data` (dict): The data to be normalized and hashed.

**Returns:**
- `bytes`: The SHA-256 hash of the normalized data in hexadecimal format.

#### `sign(self, doc: dict, creator: str, private_key: rsa.RSAPrivateKey, options: dict = None, created: datetime.datetime = None) -> dict`
Signs the provided document using the specified RSA private key.

**Args:**
- `doc` (dict): The document to be signed.
- `creator` (str): The identifier of the creator of the document.
- `private_key` (rsa.RSAPrivateKey): The RSA private key used for signing.
- `options` (dict, optional): Additional signing options. Defaults to None.
- `created` (datetime.datetime, optional): The timestamp when the signature is created. Defaults to the current UTC time if not provided.

**Returns:**
- `dict`: The signed document containing the original data and the signature.

#### `verify(self, doc: dict, public_key: rsa.RSAPublicKey | str) -> bool`
Verifies the signature of the provided document against the given public key.

**Args:**
- `doc` (dict): The signed document to verify.
- `public_key` (rsa.RSAPublicKey | str): The RSA public key in PEM format or as a multibase-encoded string.

**Returns:**
- `bool`: True if the signature is valid; otherwise, an exception is raised.

**Raises:**
- `MissingSignature`: If the signature section is missing in the document.
- `UnknownSignature`: If the signature type is not recognized.
- `VerificationFailed`: If the signature verification fails.

## Example Usage

```python
from apsig import LDSignature
from cryptography.hazmat.primitives import rsa

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()


# Example document
document = {
    "actor": "http://example.com/alice",
    "signature": {}
}

# Generate the signature
ld_signature = LDSignature()
signed_document = ld_signature.sign(document, "http://example.com/alice", private_key)
print("Generated Document with Signature:")
print(json.dumps(signed_document, indent=2))

# Verify the signature
is_valid = ld_signature.verify(signed_document, public_key)
print("Is the signature valid?", is_valid)
```

## Notes
- The `LDSignature` class assumes the usage of RSA keys and follows the signature format defined by the W3C.

## Exceptions
- **MissingSignature**: Raised when the signature section is not found in the document.
- **UnknownSignature**: Raised when the signature type is not recognized.
- **VerificationFailed**: Raised when the signature verification fails due to an invalid signature.