from apsig import KeyUtil


def fake(publicKeys: dict):
    keyutl = KeyUtil(private_key=publicKeys["ed25519-key"])
    return {
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
            "https://w3id.org/security/data-integrity/v1",
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
            "https://www.w3.org/ns/cid/v1",
        ],
        "type": "Person",
        "preferredUsername": "apsig_dev",
        "name": "APSig Test Actor",
        "summary": "testing purposes only, don't use on production environment!",
        "id": "https://apsig.amase.cc/actor",
        "inbox": "https://apsig.amase.cc/actor/inbox",
        "outbox": "https://apsig.amase.cc/actor/outbox",
        "assertionMethod": [
            {
                "id": "https://apsig.amase.cc/actor#ed25519-key",
                "type": "Multikey",
                "controller": "https://apsig.amase.cc/actor",
                "publicKeyMultibase": keyutl.encode_multibase(),
            }
        ],
        "publicKey": {
            "id": "https://apsig.amase.cc/actor#main-key",
            "controller": "https://apsig.amase.cc/actor",
            "owner": "https://apsig.amase.cc/actor",
            "publicKeyPem": publicKeys["publicKeyPem"].decode("utf-8"),
            "type": "Key"
        },
        "url": "https://apsig.amase.cc/actor"
    }