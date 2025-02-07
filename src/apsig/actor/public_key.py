from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidKey

from ..utils.multibase import multibase_encode, multibase_decode

class KeyUtil:
    def __init__(self, public_key: ed25519.Ed25519PublicKey | rsa.RSAPublicKey=None, private_key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey=None):
        """KeyUtil

        Args:
            public_key (ed25519.Ed25519PublicKey | rsa.RSAPublicKey, optional): Actor's Public Key. usually, auto generated public_key from private_key but, if private_key is none, must be set this.
            private_key (ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey, optional): Actor's Private Key. Defaults to None.
        """
        if private_key is None:
            if public_key is None:
                raise KeyError("If private_key is None, public_key must be set.")
            else:
                self.public_key = public_key
        else:
            self.private_key = private_key
            self.public_key = private_key.public_key()

    def encode_multibase(self):
        if isinstance(self.public_key, rsa.RSAPublicKey):
            return multibase_encode(self.public_key.public_bytes(encoding=serialization.Encoding.PEM), "base58btc")
        return multibase_encode(self.public_key.public_bytes_raw(), "base58btc")

    def decode_multibase(self, data: str, key_type: str="ed25519"):
        """Get PublicKey from Multibase.

        Args:
            data (str): multibase data.
            key_type (str): Type of key derived from multibase. The default is ed25519.
        """
        decoded = multibase_decode(data)
        if key_type.lower() == "ed25519":
            try:
                return ed25519.Ed25519PublicKey.from_public_bytes(decoded)
            except InvalidKey:
                raise Exception("Invalid ed25519 public key passed.") # Tempolary, will replaced apsig's exception
        elif key_type.lower() == "rsa":
            try:
                return serialization.load_pem_public_key(decoded)
            except ValueError:
                raise Exception("Invalid rsa public key passed.") # Tempolary, will replaced apsig's exception