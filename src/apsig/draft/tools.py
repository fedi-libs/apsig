import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def calculate_digest(body: bytes | str):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(body.encode("utf-8") if isinstance(body, str) else body)
    hash_bytes = digest.finalize()
    return "SHA-256=" + base64.standard_b64encode(hash_bytes).decode("utf-8")

def build_string(strings: dict, headers: list = []) -> str:
    if headers:
        header_list = []
        for key in headers:
            header_list.append(f"{key}: {strings[key.lower()]}")
        result = "\n".join(header_list)
    else:
        result = "\n".join(f"{key.lower()}: {value}" for key, value in strings.items())
    return result