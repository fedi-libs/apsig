import hashlib

import jcs
from cryptography.hazmat.primitives.asymmetric import ed25519
from multiformats import multibase, multicodec


class ProofSigner:
    """
    A class for signing documents using the Ed25519 signature algorithm, 
    implementing Object Integrity Proofs as specified in FEP-8b32.

    This class provides methods to generate keys, sign data, 
    canonicalize documents, and create integrity proofs.

    Attributes:
        private_key (ed25519.Ed25519PrivateKey): The Ed25519 private key used for signing.
        public_key (ed25519.Ed25519PublicKey): The corresponding Ed25519 public key.

    Methods:
        create_proof(unsecured_document: dict, options: dict) -> dict:
            Creates a proof for the unsecured document using the specified options.

        sign(unsecured_document: dict, options: dict) -> dict:
            Signs the unsecured document by creating a proof and returning the signed document.
    """

    def __init__(self, private_key: ed25519.Ed25519PrivateKey | str):
        if isinstance(private_key, str):
            codec, data = multicodec.unwrap(multibase.decode(private_key))
            if codec.name != "ed25519-priv":
                raise TypeError("PrivateKey must be ed25519.")
            else:
                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(data)
        self.private_key, self.public_key = private_key, private_key.public_key()

    def sign_data(self, hash_data):
        return self.private_key.sign(hash_data)

    def canonicalize(self, document):
        return jcs.canonicalize(document)

    def transform(self, unsecured_document, options):
        if (
            options["type"] != "DataIntegrityProof"
            or options["cryptosuite"] != "eddsa-jcs-2022"
        ):
            raise ValueError("PROOF_VERIFICATION_ERROR")

        canonical_document = self.canonicalize(unsecured_document)
        return canonical_document

    def hashing(self, transformed_document, canonical_proof_config):
        transformed_document_hash = hashlib.sha256(
            transformed_document.encode("utf-8") if not isinstance(transformed_document, bytes) else transformed_document
        ).digest()
        proof_config_hash = hashlib.sha256(
            canonical_proof_config.encode("utf-8") if not isinstance(canonical_proof_config, bytes) else canonical_proof_config
        ).digest()
        return proof_config_hash + transformed_document_hash

    def create_proof(self, unsecured_document, options):
        """Creates a proof for the unsecured document using the specified options.

        Args:
            unsecured_document (dict): The document for which the proof is created.
            options (dict): Options that define how the proof is structured.

        Returns:
            dict: The proof object containing the proof value and other relevant information.
        """
        proof = options.copy()

        if "@context" in unsecured_document:
            proof["@context"] = unsecured_document["@context"]

        proof_config = self.canonicalize(proof)
        transformed_data = self.transform(unsecured_document, options)
        hash_data = self.hashing(transformed_data, proof_config)
        proof_bytes = self.sign_data(hash_data)

        proof["proofValue"] = multibase.encode(proof_bytes, "base58btc")
        return proof
    
    def sign(self, unsecured_document: dict, options: dict):
        """Signs the unsecured document by creating a proof and returning the signed document.

        Args:
            unsecured_document (dict): The document to be signed.
            options (dict): Options that define the signing process.

        Returns:
            dict: The signed document, including the proof.
        """
        return {**unsecured_document, "proof": self.create_proof(unsecured_document, options)}

