import asyncio
import datetime
from pprint import pprint
import random
import json

import aiohttp
import uvicorn
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from faker.actor import fake
from yarl import URL
from notturno import Notturno
from notturno.models.request import Request

from apsig.rfc9421 import RFC9421Signer

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
    user_pin = int(request.query.get("pin", b'0'))
    if user_pin != pin:
        return {"error": "Missing Permission"}
    url = request.query.get("url", b'None').decode()

    if url == "None":
        return {"error": "url is required"}
    #await asyncio.sleep(3)
    #return {"resp": "Failed to verify the request signature.", "status": 401}
    async with aiohttp.ClientSession() as session:
        body = {
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/data-integrity/v1",
            ],
            "id": "https://apsig.amase.cc/note",
            "actor": "https://apsig.amase.cc/actor",
            "type": "Create",
            "object": {
                "id": "https://apsig.amase.cc/note",
                "type": "Note",
                "attributedTo": "https://apsig.amase.cc/actor",
                "content": "Hello world",
            },
        }
        target = URL(url)
        signer = RFC9421Signer(private_key=ed_privatekey, key_id="https://apsig.amase.cc/actor#ed25519-key")
        signed = signer.sign(body=body, method="POST", path=target.path, host=target.host + ":" + str(target.port) if target.port is not None else "", headers={"Content-Type": "application/activity+json"})
        with open("./test.json", "w") as f:
            json.dump(signed, f)

        pprint(signed)
        async with session.post(
            url,
            json=body,
            headers=signed,
        ) as resp:
            text = await resp.text()
            status = resp.status
            print(text)
            print(status)
            return {"resp": text, "status": status}


pin = random.randint(1000, 9999)
#pin = 1751
print("Server Pin is: " + str(pin))
uvicorn.run(app, host="0.0.0.0")
