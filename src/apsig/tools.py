from typing import Any

def get_draft_signature_parts(signature: str) -> dict[Any, Any]:
    signature_parts = {}
    for item in signature.split(","):
        key, value = item.split("=", 1)
        signature_parts[key.strip()] = value.strip().strip('"')
    return signature_parts