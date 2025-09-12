import base64
import email.utils
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from http_sf import ser, parse

from .exceptions import VerificationFailed, MissingHeader

class RFC9421Signer:
    def __init__(self, private_key: ed25519.Ed25519PrivateKey, key_id: str):
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise TypeError("private_key must be an Ed25519PrivateKey.")
        self.private_key = private_key
        self.key_id = key_id
        self.sign_headers = ["@method", "@authority", "@target-uri", "date", "host"] # ["@method", "@path", "@authority", "date", "content-digest"] , "content-length"

    def _build_signature_base(self, special_keys: dict, headers: dict, created: int) -> bytes:
        params = {
            "alg": "ed25519",
            "keyid": self.key_id,
            "created": created
        }

        signature_base_list = []
        for h in self.sign_headers:
            if h.startswith("@"):
                value = special_keys.get(h)
                if value is None:
                    raise ValueError(f"Missing required special key: {h}")
                signature_base_list.append((h, value))
            else:
                value = headers.get(h.lower())
                if value is None:
                    raise MissingHeader(f"Missing required header: {h}")
                signature_base_list.append((h, value))

        base_string = ""
        for i, (header, value) in enumerate(signature_base_list):
            base_string += f'"{header}": {value}'
            if i < len(signature_base_list) - 1:
                base_string += "\n"

        sig_params_string = ser(params)
        base_string += f'\n"@signature-params": {sig_params_string}'
        
        return base_string.encode("utf-8")

    def __digest(self, body: bytes | str):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(body.encode("utf-8") if isinstance(body, str) else body)
        
        #digest = hashlib.sha256(bytes(body) if isinstance(body, str) else body).digest()
        return digest.finalize()
    
    def sign(self, method: str, url: str, host: str, headers: dict, body: bytes | dict = b"") -> dict:
        if isinstance(body, dict):
            body = json.dumps(body, separators=( ",", ":" ), allow_nan=False).encode("utf-8")

        headers = {k.lower(): v for k, v in headers.items()}

        if "date" not in headers:
            headers["date"] = email.utils.formatdate(usegmt=True)
        if "host" not in headers:
            headers["host"] = host
        if "content-digest" not in headers:
            
            headers["Content-Digest"] = ser({"sha-256": self.__digest(body)}) # f"sha-256=:{calculate_digest(body)}:"

        special_keys = {
            "@method": method.upper(),
            "@target-uri": url,
            "@authority": host,
        }

        created = int(datetime.now(timezone.utc).timestamp())
        
        base = self._build_signature_base(special_keys, headers, created)
        
        signed_bytes = self.private_key.sign(base)
        signature = base64.b64encode(signed_bytes).decode("utf-8")

        sig_input_params = {
            "alg": "ed25519",
            "keyid": f'"{self.key_id}"',
            "created": created,
        }
        
        headers["Signature-Input"] = f"""sig1=({" ".join(f'"{header}"' for header in self.sign_headers)});{";".join(f"{k}={v}" for k, v in sig_input_params.items())}"""
        headers["Signature"] = f"sig1=:{signature}:"
        
        return headers

class RFC9421Verifier:
    """
    Verifies an HTTP message signature according to RFC 9421.
    """
    def __init__(self, public_key_resolver):
        """
        Args:
            public_key_resolver: A callable that takes a key_id (str) and returns an Ed25519PublicKey.
        """
        self.public_key_resolver = public_key_resolver

    def _rebuild_signature_base(self, special_keys: dict, headers: dict, signature_input: dict) -> bytes:
        """
        Reconstructs the signature base string for verification.
        """
        signed_headers = signature_input["fields"]
        params = signature_input["params"]

        base_list = []
        for h in signed_headers:
            if h.startswith("@"):
                value = special_keys.get(h)
                if value is None:
                    raise ValueError(f"Missing required special key from input: {h}")
                base_list.append((h, value))
            else:
                value = headers.get(h.lower())
                if value is None:
                    raise MissingHeader(f"Missing required header from input: {h}")
                base_list.append((h, value))
        
        base_string = ""
        for i, (header, value) in enumerate(base_list):
            base_string += f'"{header}": {value}'
            if i < len(base_list) - 1:
                base_string += "\n"
        
        # Add the signature parameters to the base
        sig_params_string = ser(params)
        base_string += f'\n"@signature-params": {sig_params_string}'

        return base_string.encode("utf-8")

    def verify(self, method: str, path: str, host: str, headers: dict) -> bool:
        """
        Verifies the signature of the incoming request.
        """
        headers = {k.lower(): v for k, v in headers.items()}
        
        sig_input_header = headers.get("signature-input")
        signature_header = headers.get("signature")

        if not sig_input_header or not signature_header:
            raise VerificationFailed("Missing 'Signature-Input' or 'Signature' header.")

        # Parse the Signature-Input header
        parsed_sig_input = parse(sig_input_header.encode("utf-8"), tltype="dictionary")
        sig1_input = parsed_sig_input.get("sig1")
        if not sig1_input:
            raise VerificationFailed("Invalid 'Signature-Input' format.")
            
        signed_fields = [item for item in sig1_input[0]]
        params = sig1_input[1]

        key_id = params.get("keyid")
        if not key_id:
            raise VerificationFailed("Missing 'keyid' in signature parameters.")

        public_key = self.public_key_resolver(key_id)
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise VerificationFailed(f"Could not resolve a valid public key for keyId: {key_id}")

        special_keys = {
            "@method": method.upper(),
            "@path": path,
            "@authority": host,
        }
        
        signature_input_dict = {"fields": signed_fields, "params": params}
        
        base_to_verify = self._rebuild_signature_base(special_keys, headers, signature_input_dict)
        
        # Extract the signature value
        parsed_signature = parse(signature_header.encode("utf-8"), tltype="dictionary")
        sig1_signature = parsed_signature.get("sig1")
        if not sig1_signature:
            raise VerificationFailed("Invalid 'Signature' header format.")
        
        signature_bytes = base64.b64decode(sig1_signature[0])

        try:
            public_key.verify(signature_bytes, base_to_verify)
            return True
        except InvalidSignature:
            raise VerificationFailed("Signature verification failed.")