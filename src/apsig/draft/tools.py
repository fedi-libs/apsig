import base64

import hashlib

def calculate_digest(body: bytes | str):
    digest = hashlib.sha256(body.encode("utf-8") if isinstance(body, str) else body).digest()
    hash_bytes = digest
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