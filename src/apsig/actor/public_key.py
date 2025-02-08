from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidKey

from multiformats import multibase, multicodec

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
            return multibase.encode(self.public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.PKCS1).hex(), "base58btc")
        prefixed = multicodec.wrap("ed25519-pub", self.public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))
        return multibase.encode(prefixed, "base58btc") # .hex().encode("utf-8")

    def decode_multibase(self, data: str, key_type: str="ed25519"):
        """Get PublicKey from Multibase.

        Args:
            data (str): multibase data.
            key_type (str): Type of key derived from multibase. The default is ed25519.
        """
        decoded = multibase.decode(data)
        if key_type.lower() == "ed25519":
            try:
                return ed25519.Ed25519PublicKey.from_public_bytes(decoded)
            except InvalidKey:
                raise Exception("Invalid ed25519 public key passed.") # Tempolary, will replaced apsig's exception
        elif key_type.lower() == "rsa":
            try:
                return serialization.load_der_public_key(decoded)
            except ValueError:
                raise Exception("Invalid rsa public key passed.") # Tempolary, will replaced apsig's exception