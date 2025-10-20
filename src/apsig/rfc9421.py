import base64
import email.utils
import json

from cryptography.hazmat.primitives.asymmetric import ed25519
from pyfill.datetime import utcnow

from apsig.draft.tools import calculate_digest


class RFC9421Signer:
    def __init__(self, private_key: ed25519.Ed25519PrivateKey, key_id: str):
        self.private_key = private_key
        self.key_id = key_id
        self.sign_headers = [
            "date",
            "@method",
            "@path",
            "@authority",
            "content-type",
            "content-length",
        ]

    def build_base(self, special_keys: dict, headers: dict) -> bytes:
        headers_new = ""
        headers = headers.copy()
        for h in self.sign_headers:
            if h in ["@method", "@path", "@authority"]:
                v = special_keys.get(h)

                if v:
                    headers_new += f'"{h}": {v}\n'
                else:
                    raise ValueError(f"Missing Value: {h}")
            elif h == "@signature-params":
                v = special_keys.get(h)

                if v:
                    headers_new += f'"{h}": {self.__generate_sig_input()}\n'
                else:
                    raise ValueError(f"Missing Value: {h}")
            else:
                v = headers.get(h)
                if v:
                    headers_new += f'"{h}": {v}\n'
                else:
                    raise ValueError(f"Missing Header Value: {h}")
        return headers_new.encode("utf-8")

    def __build_signature_base(
        self, special_keys: dict[str, str], headers: dict[str, str]
    ) -> bytes:
        headers_new = []
        headers = headers.copy()
        for h in self.sign_headers:
            if h in ["@method", "@path", "@authority"]:
                v = special_keys.get(h)

                if v:
                    headers_new.append(f'"{h}": {v}')
                else:
                    raise ValueError(f"Missing Value: {h}")
            elif h == "@signature-params":
                v = special_keys.get(h)

                if v:
                    headers_new.append(f'"{h}": {self.__generate_sig_input()}')
                else:
                    raise ValueError(f"Missing Value: {h}")
            else:
                v = headers.get(h)
                if v:
                    headers_new.append(f'"{h}": {v}')
                else:
                    raise ValueError(f"Missing Header Value: {h}")
        headers_new.append(
            f'"@signature-params": {self.__generate_sig_input()}'
        )
        return "\n".join(headers_new)

    def generate_signature_header(self, signature: bytes) -> str:
        return base64.b64encode(signature).decode("utf-8")

    def __generate_sig_input(self):
        param = "("
        target_len = len(self.sign_headers)
        timestamp = utcnow()
        for p in self.sign_headers:
            param += f'"{p}"'
            if p != self.sign_headers[target_len - 1]:
                param += " "
        param += ");"
        param += f"created={int(timestamp.timestamp())};"
        param += f'keyid="{self.key_id}"'
        return param

    def sign(
        self,
        method: str,
        path: str,
        host: str,
        headers: dict,
        body: bytes | dict = b"",
    ):
        if isinstance(body, dict):
            body = json.dumps(body).encode("utf-8")

        if not headers.get("Date"):
            headers["Date"] = email.utils.formatdate(usegmt=True)
        if (
            headers.get("content-length") is None
            or headers.get("Content-Length") is None
        ):
            headers["content-length"] = str(len(body))
        headers = {k.lower(): v for k, v in headers.items()}
        special_keys = {
            "@method": method.upper(),
            "@path": path,
            "@authority": host,
        }

        base = self.__build_signature_base(special_keys, headers)
        signed = self.private_key.sign(base)
        headers_req = headers.copy()
        headers_req["Signature"] = (
            f"sig1=:{self.generate_signature_header(signed)}:"
        )
        headers_req["content-digest"] = f"sha-256=:{calculate_digest(body)}:"
        headers_req["Signature-Input"] = f"sig1={self.__generate_sig_input()}"
        return headers_req


class RFC9421Verifier:
    def __init__(self):
        pass

    def __build_signature_base(
        self, special_keys: dict[str, str], headers: dict[str, str]
    ) -> bytes:
        headers_new = []
        headers = headers.copy()
        for h in self.sign_headers:
            if h in ["@method", "@path", "@authority"]:
                v = special_keys.get(h)

                if v:
                    headers_new.append(f'"{h}": {v}')
                else:
                    raise ValueError(f"Missing Value: {h}")
            elif h == "@signature-params":
                v = special_keys.get(h)

                if v:
                    headers_new.append(f'"{h}": {self.__generate_sig_input()}')
                else:
                    raise ValueError(f"Missing Value: {h}")
            else:
                v = headers.get(h)
                if v:
                    headers_new.append(f'"{h}": {v}')
                else:
                    raise ValueError(f"Missing Header Value: {h}")
        headers_new.append(
            f'"@signature-params": {self.__generate_sig_input()}'
        )
        return "\n".join(headers_new)

    def verify(self):
        raise NotImplementedError


priv = ed25519.Ed25519PrivateKey.generate()
signer = RFC9421Signer(priv, "")
print(signer.sign("post", "/", "example.com", {"Content-Type": "application/json", "Content-Length": 18, "Date": "Tue, 20 Apr 2021 02:07:55 GMT"}, {"key": "value"})) # '{"key": "value"}'
