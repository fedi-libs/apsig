import datetime
from pprint import pprint
import random

import aiohttp
import uvicorn
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from faker.actor import fake
from notturno import Notturno
from notturno.models.request import Request

from apsig import ProofSigner

app = Notturno()
ed_privatekey = ed25519.Ed25519PrivateKey.generate()
rsa_privatekey = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
actor_obj = fake(
    {
        "ed25519-key": ed_privatekey,
        "publicKeyPem": rsa_privatekey.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    }
)
Proof = ProofSigner(private_key=ed_privatekey)
now = datetime.datetime.now().isoformat(sep="T", timespec="seconds") + "Z"


@app.get("/actor")
async def actor():
    return actor_obj


@app.post("/inbox")
async def inbox(request: Request):
    print(request.body)


@app.get("/note")
async def note():
    return {
        "@context": "https://www.w3.org/ns/activitystreams",
        "type": "Note",
        "id": "https://apsig.amase.cc/note",
        "attributedTo": "https://apsig.amase.cc/actor",
        "content": "Hello world",
        "published": now,
        "to": [
            "https://www.w3.org/ns/activitystreams#Public",
        ],
    }


@app.get("/send")
async def send(request: Request):
    user_pin = request.query.get("pin")
    if user_pin != pin:
        return {"error": "Missing Permission"}
    url = request.query.get("url")
    if url is None:
        return {"error": "url is required"}
    async with aiohttp.ClientSession() as session:
        body = {
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/data-integrity/v1",
            ],
            "id": "https://apsig.amase.cc/note",
            "actor": actor_obj,
            "type": "Create",
            "object": {
                "id": "https://apsig.amase.cc/note",
                "type": "Note",
                "attributedTo": "https://apsig.amase.cc/actor",
                "content": "Hello world",
            },
        }
        signed = Proof.sign(
            unsecured_document=body,
            options={
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "proofPurpose": "assertionMethod",
                "verificationMethod": "https://apsig.amase.cc/actor#ed25519-key",
                "created": now,
            },
        )
        pprint(signed)
        async with session.post(
            url.decode("utf-8"),
            json=signed,
            headers={"Content-Type": "application/activity+json"},
        ) as resp:
            print(await resp.text())
            print(resp.status)


pin = random.randint(1000, 9999)
print("Server Pin is: " + str(pin))
uvicorn.run(app, host="0.0.0.0")
