import base64
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from apsig.draft.tools import calculate_digest

class RFC9421Signer:
    def __init__(self, private_key: ed25519.Ed25519PrivateKey, method: str, path: str, host: str, headers: dict):
        self.private_key = private_key
        self.headers =  {k.lower(): v for k, v in headers.items()}
        self.sign_headers = ["date", "@method", "@path", "@authority", "content-type", "content-length"]
        self.special_keys = {
            "@method": method.upper(),
            "@path": path,
            "@authority": host
        }

    def build_base(self) -> bytes:
        headers_new = ""
        headers = self.headers.copy()
        for h in self.sign_headers:
            if h in ["@method", "@path", "@authority"]:
                v = self.special_keys.get(h)
                if v:
                    headers_new += f'"{h}": {v}\n'
                else:
                    raise ValueError(f"Missing Value: {h}")
            else:
                v = headers.get(h)
                if v:
                    headers_new += f'"{h}": {v}\n'
                else:
                    raise ValueError(f"Missing Header Value: {h}")
        return headers_new.encode("utf-8")

    def generate_signature_header(self, signature: bytes) -> str:
        return base64.urlsafe_b64encode(signature).decode("utf-8")

    def __generate_sig_input(self):
        param = "("
        target_len = len(self.sign_headers)
        for p in self.sign_headers:
            param += f'"{p}"'
            if p != self.sign_headers[target_len - 1]:
                param += " "
        param += ");"
        param += "created=1618884473;"
        param += 'keyid="test-key-ed25519"'
        return param

    def __generate_rfc8792_digest(self):
        pass

    def sign(self, body: bytes | dict=b""):
        if isinstance(body, dict):
            body = json.dumps(body).encode("utf-8")

        base = self.build_base()
        signed = self.private_key.sign(base)
        headers = self.headers.copy()
        headers["signature"] = f"sig-b26=:{self.generate_signature_header(signed)}:"
        headers["content-digest"] = f"sha-256=:{calculate_digest(body)}:"
        headers["@signature-params"] = f"sig-b26=:{self.__generate_sig_input()}:"
        return headers

class RFC9421Verifier:
    def __init__(self):
        pass

    def verify(self):
        raise NotImplementedError
    
# priv = ed25519.Ed25519PrivateKey.generate()
# signer = RFC9421Signer(priv, "post", "/", "example.com", {"Content-Type": "application/json", "Content-Length": 18, "Date": "Tue, 20 Apr 2021 02:07:55 GMT"})
# print(signer.sign({"key": "value"})) # '{"key": "value"}'