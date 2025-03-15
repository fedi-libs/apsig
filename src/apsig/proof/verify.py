from typing import Union
import hashlib

import jcs
from cryptography.hazmat.primitives.asymmetric import ed25519
from multiformats import multibase, multicodec

from ..exceptions import VerificationFailed, UnknownSignature

class ProofVerifier:
    """
    A class for verifying documents signed using the Ed25519 signature algorithm, 
    implementing Object Integrity Proofs as specified in FEP-8b32.
    
    Attributes:
        public_key (ed25519.Ed25519PublicKey): The Ed25519 public key used for verification.

    Methods:
        verify_proof(secured_document: dict) -> dict:
            Verifies the proof contained in the secured document.
        verify(secured_document: dict) -> dict:
            An alias for the verify_proof method.
    """

    def __init__(self, public_key: ed25519.Ed25519PublicKey | str):
        """
        Initializes the ProofVerifier with a public key.

        Args:
            public_key (ed25519.Ed25519PublicKey | str): 
                The Ed25519 public key as an object or a multibase-encoded string.

        Raises:
            TypeError: If the provided public key is not of type Ed25519.
        """
        if isinstance(public_key, str):
            codec, data = multicodec.unwrap(multibase.decode(public_key))
            if codec.name != "ed25519-pub":
                raise TypeError("PublicKey must be ed25519.")
            self.public_key: ed25519.Ed25519PublicKey = (
                ed25519.Ed25519PublicKey.from_public_bytes(data)
            )
        else:
            self.public_key: ed25519.Ed25519PublicKey = public_key

    def verify_signature(self, signature, hash_data):
        self.public_key.verify(signature, hash_data)

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

    def verify_proof(self, secured_document: dict, raise_on_fail: bool = False) -> Union[str, bool]:
        """
        Verifies the proof contained in the secured document.

        This method checks the integrity and authenticity of the secured document 
        by validating the associated proof. It verifies the signature against the 
        hash of the transformed document and the canonical proof configuration.

        Args:
            secured_document (dict): The document containing the proof to be verified.
            raise_on_fail (bool, optional): Return error on failure. defaults to False.

        Returns:
            dict: A dictionary containing:
                - bool: `verified`: Indicates whether the proof verification was successful.
                - dict: `verifiedDocument`: The unsecured document if verification was successful, otherwise `None`.

        Raises:
            ValueError: If the proof is not found in the document.
        """
        if not secured_document.get("proof"):
            if raise_on_fail:
                raise ValueError("Proof not found in the object")
            return None
        unsecured_document = secured_document.copy()
        proof_value = unsecured_document["proof"].pop("proofValue")
        proof_bytes = multibase.decode(proof_value)

        proof_options = unsecured_document["proof"]
        verification_method = proof_options.get("verificationMethod")
        if not verification_method:
            if raise_on_fail:
                raise ValueError("verificationMethod not found in proof")
            return None

        if "@context" in proof_options:
            if isinstance(secured_document["@context"], str):
                if not secured_document["@context"].startswith(
                    tuple(proof_options["@context"])
                ):
                    if raise_on_fail:
                        raise UnknownSignature
                    return None
            elif isinstance(secured_document["@context"], list):
                if not any(item.startswith(tuple(proof_options["@context"])) for item in secured_document["@context"] if isinstance(item, str)):
                    if raise_on_fail:
                        raise UnknownSignature
                    return None


        unsecured_document.pop("proof")
        transformed_data = self.transform(unsecured_document, proof_options)
        proof_config = self.canonicalize(proof_options)
        hash_data = self.hashing(transformed_data, proof_config)

        try:
            self.verify_signature(proof_bytes, hash_data)
            return verification_method
        except Exception as e:
            if raise_on_fail:
                raise VerificationFailed(str(e))
            return None

    def verify(self, secured_document: dict, raise_on_fail: bool = False) -> Union[str, bool]:
        """
        An alias for the verify_proof method.

        This method calls verify_proof to perform the actual verification 
        of the proof contained in the secured document.

        Args:
            secured_document (dict): The document containing the proof to be verified.

        Returns:
            dict: The result of the proof verification.
        """
        return self.verify_proof(secured_document, raise_on_fail)