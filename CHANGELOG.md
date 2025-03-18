# 0.5.1
## Bug Fixed
- fix: To accept RSAPublicKey format, and body also supports dictionary format.
# 0.5.0
Following on from the last one, this is another revision involving major changes 🤯
## New Features
- feat: To make only the analysis available
- feat: Unless otherwise specified, “None” is returned if verification fails. On success, return keyId.
## Bug Fixed
- fix: Fixed incorrect hash generation
# 0.4.0
This is a major release containing disruptive changes! 💣
## Bug Fixed
- fix(draft): include Host header in signatures
## Deprecation
- `apsig.draft.sign.draftSigner` has been deprecated and will be removed in 1.0, please use `apsig.draft.sign.Signer` instead.
- `apsig.draft.verify.draftVerifier` has been deprecated and will be removed in 1.0, please use `apsig.draft.verify.Verifier` instead.
# 0.3.2
## Bug Fixed
- fix: convert header keys to case-insensitive key names during validation
# 0.3.1
## Bug Fixed
- fix: Fixed problem with HTTP signatures not being accepted in some implementations
# 0.3.0
## Bug Fixed
- fix: Correct FEP-8b32 Implemention
- fix: use pkcs#1 der on encodeing public key
- fix: FEP-8b32 implementation verifiable with Fedify
- feat: A working implementation of Linked Data Signature 1.0
## Others
- chore: drop 3.9
