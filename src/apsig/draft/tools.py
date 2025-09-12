import base64

import hashlib

def calculate_digest(body: bytes | str):
    digest = hashlib.sha256(body.encode("utf-8") if isinstance(body, str) else body).digest()
    hash_bytes = digest
    return "SHA-256=" + base64.standard_b64encode(hash_bytes).decode("utf-8")

def build_string(strings: dict, headers: list) -> str:
    """Builds the signing string from a dictionary of headers and a list of header names.

    Args:
        strings (dict): A dictionary containing header values, with lowercase keys.
        headers (list): An ordered list of lowercase header names to include in the string.

    Returns:
        str: The formatted signing string.
    """
    return "\n".join(f"{key}: {strings[key]}" for key in headers)