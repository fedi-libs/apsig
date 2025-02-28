
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidKey

from multiformats import multibase, multicodec


class KeyUtil:
    def __init__(
        self,
        public_key: ed25519.Ed25519PublicKey | rsa.RSAPublicKey = None,
        private_key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey = None,
    ):
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

    def encode_multibase(self, private: bool = False) -> str:
        """multibase encode the key.

        Args:
            private (bool, optional): If true, decodes/encodes the private key, not the public key. Defaults to False.

        Returns:
            str: multibase encoded string.
        """
        if not private:
            if isinstance(self.public_key, rsa.RSAPublicKey):
                prefixed = multicodec.wrap(
                    "rsa-pub",
                    self.public_key.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.PKCS1,
                    ).hex(),
                )
            prefixed = multicodec.wrap(
                "ed25519-pub",
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                ),
            )
        else:
            if isinstance(self.private_key, rsa.RSAPrivateKey):
                prefixed = multicodec.wrap(
                    "rsa-priv",
                    self.public_key.public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.PKCS1,
                    ).hex(),
                )
            else:
                prefixed = multicodec.wrap(
                    "ed25519-priv",
                    self.public_key.public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    ),
                )
        return multibase.encode(prefixed, "base58btc")

    def decode_multibase(
        self, data: str
    ) -> (
        ed25519.Ed25519PublicKey
        | ed25519.Ed25519PrivateKey
        | rsa.RSAPublicKey
        | rsa.RSAPrivateKey
    ):
        """Get Public/PrivateKey from Multibase.

        Args:
            data (str): multibase data.

        Raises:
            Exception: _description_
            Exception: _description_
            Exception: _description_
            Exception: _description_
            ValueError: _description_

        Returns:
            ed25519.Ed25519PublicKey | ed25519.Ed25519PrivateKey | rsa.RSAPublicKey | rsa.RSAPrivateKey: Loaded Key Object.
        """
        decoded = multibase.decode(data)
        codec, data = multicodec.unwrap(decoded)
        if codec.name == "ed25519-pub":
            try:
                return ed25519.Ed25519PublicKey.from_public_bytes(data)
            except InvalidKey:
                raise Exception(
                    "Invalid ed25519 public key passed."
                )  # Tempolary, will replaced apsig's exception
        elif codec.name == "rsa-pub":
            try:
                rsa.RSAPublicKey
                return serialization.load_der_public_key(data)
            except ValueError:
                raise Exception(
                    "Invalid rsa public key passed."
                )  # Tempolary, will replaced apsig's exception
        if codec.name == "ed25519-priv":
            try:
                return ed25519.Ed25519PrivateKey.from_private_bytes(data)
            except InvalidKey:
                raise Exception(
                    "Invalid ed25519 private key passed."
                )  # Tempolary, will replaced apsig's exception
        elif codec.name == "rsa-priv":
            try:
                return serialization.load_der_private_key(data)
            except ValueError:
                raise Exception(
                    "Invalid rsa private key passed."
                )  # Tempolary, will replaced apsig's exception
        else:
            raise ValueError("Unsupported Codec: {}".format(codec.name))
