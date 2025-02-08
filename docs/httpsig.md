# `apsig.draft`
HTTP signature implementation based on [draft-cavage-http-signatures-12](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12).
## `apsig.draft.draftSigner`
### Overview
The `sign` method generates a digital signature based on the given HTTP request details and adds it to the HTTP headers.

### Signature
```python
def sign(private_key: rsa.RSAPrivateKey, method: str, url: str, headers: dict, key_id: str, body: bytes="") -> dict
```

### Parameters
- **`private_key`**: `rsa.RSAPrivateKey`
  - The RSA private key used to generate the signature.

- **`method`**: `str`
  - The HTTP method (e.g., `"GET"`, `"POST"`).

- **`url`**: `str`
  - The URL of the request.

- **`headers`**: `dict`
  - A dictionary of HTTP headers that will be signed. The signature will be added to this dictionary.

- **`key_id`**: `str`
  - The key identifier that will be included in the signature header.

- **`body`**: `bytes`
  - The request body. Defaults to an empty byte string.

### Returns
- A dictionary of HTTP headers with the signature added.

### Example Usage
Here’s an example of how to use the `sign` method.

#### Example
```python
from cryptography.hazmat.primitives import rsa
from apsig import draftSigner

# Generate an RSA private key (example)
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# HTTP request details
method = "POST"
url = "https://example.com/api"
headers = {
    "Content-Type": "application/json",
    "Date": "Wed, 21 Oct 2015 07:28:00 GMT"
}
key_id = "my-key-id"
body = '{"key": "value"}'.encode("utf-8")

# Generate the signature
signed_headers = draftSigner.sign(private_key, method, url, headers, key_id, body)

print(signed_headers)
```

### Notes
- You need to have an RSA private key ready before generating the signature.
- The generated signature will be added to the HTTP request headers and sent along with the request. 
## `apsig.draft.draftVerifier`

### Overview
The `verify` method checks the validity of a digital signature based on the provided HTTP request details, public key, and request body. It ensures that the signature is correct, the digest matches, and the request is timely.

### Signature
```python
def verify(public_pem: str, method: str, url: str, headers: dict, body: bytes=b"") -> tuple
```

### Parameters
- **`public_pem`**: `str`
  - The public key in PEM format used to verify the signature.

- **`method`**: `str`
  - The HTTP method (e.g., `"GET"`, `"POST"`).

- **`url`**: `str`
  - The URL of the request.

- **`headers`**: `dict`
  - A dictionary of HTTP headers that includes the signature and other relevant information.

- **`body`**: `bytes`
  - The request body. Defaults to an empty byte string.

### Returns
- A tuple: `(bool, str)`
  - The first element is `True` if the signature is valid, or `False` otherwise.
  - The second element is a message indicating the result of the verification.

### Example Usage
Here’s an example of how to use the `verify` method.

#### Example
```python
from cryptography.hazmat.primitives import rsa
from apsig import draftVerifier

# Assume we have a generated RSA public key in PEM format
public_key_pem = """
-----BEGIN PUBLIC KEY-----
... (your public key here) ...
-----END PUBLIC KEY-----
"""

# HTTP request details
method = "POST"
url = "https://example.com/api"
headers = {
    "Content-Type": "application/json",
    "Date": "Wed, 21 Oct 2015 07:28:00 GMT",
    "signature": 'keyId="my-key-id",algorithm="rsa-sha256",headers="(request-target) Content-Type Date",signature="..."',
    "digest": "SHA-256=...",
}
body = '{"key": "value"}'.encode("utf-8")

# Verify the signature
is_valid, message = draftVerifier.verify(public_key_pem, method, url, headers, body)

print(is_valid)  # True or False
print(message)   # Verification result message
```

### Notes
- Ensure that the public key is correctly formatted in PEM before using it for verification.
- The `signature` and `digest` headers must be present in the `headers` dictionary for verification to succeed.
- The method checks the freshness of the request by comparing the `Date` header with the current time, allowing a maximum difference of one hour. 