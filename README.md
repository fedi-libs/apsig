# apsig
![PyPI](https://img.shields.io/pypi/v/apsig)
 [![CodeQL](https://github.com/AmaseCocoa/apsig/actions/workflows/github-code-scanning/codeql/badge.svg?branch=main)](https://github.com/AmaseCocoa/apsig/actions/workflows/github-code-scanning/codeql)

> [!IMPORTANT]
> The Linked Data Signatures 1.0 implementation is currently not working properly. [#9](https://github.com/AmaseCocoa/apsig/issues/9)

Signature implementation used in ActivityPub.

This library implements the creation/verification of signatures for HTTP Signatures ([draft-cavage-http-signatures-12](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12)), [Linked Data Signatures](https://docs.joinmastodon.org/spec/security/#ld), and Object Integrity Proofs ([FEP-8b32](https://codeberg.org/fediverse/fep/src/branch/main/fep/8b32/fep-8b32.md)).
## Installation
apsig is available on PyPI and can be installed with the following command.
```
pip install apsig
```
## Thanks
- [Hong Minhee](https://github.com/dahlia) ([Fedify](https://fedify.dev/) Author)
- [Takahē](https://github.com/jointakahe/takahe) Authors (apsig.LDSignature was ported from Takahē)
- And All Contributor/Users