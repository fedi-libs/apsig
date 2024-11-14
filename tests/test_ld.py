import unittest
from apsig import JSONLDSigner

class TestJsonLdSigner(unittest.TestCase):

    def setUp(self):
        self.signer = JSONLDSigner()
        self.data = {
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/v1",
                {
                    "Key": "sec:Key",
                    "manuallyApprovesFollowers": "as:manuallyApprovesFollowers",
                    "sensitive": "as:sensitive",
                    "Hashtag": "as:Hashtag",
                    "quoteUrl": "as:quoteUrl",
                    "toot": "http://joinmastodon.org/ns#",
                    "Emoji": "toot:Emoji",
                    "featured": "toot:featured",
                    "discoverable": "toot:discoverable",
                    "schema": "http://schema.org#",
                    "PropertyValue": "schema:PropertyValue",
                    "value": "schema:value",
                    "misskey": "https://misskey-hub.net/ns#",
                    "_misskey_content": "misskey:_misskey_content",
                    "_misskey_quote": "misskey:_misskey_quote",
                    "_misskey_reaction": "misskey:_misskey_reaction",
                    "_misskey_votes": "misskey:_misskey_votes",
                    "_misskey_summary": "misskey:_misskey_summary",
                    "isCat": "misskey:isCat",
                    "vcard": "http://www.w3.org/2006/vcard/ns#"
                }
            ],
            "type": "Note",
            "content": "Hello, world!"
        }
        self.headers = {
            'host': 'example.com'
        }

    def test_sign_and_verify(self):
        signature_header, normalized_data = self.signer.sign(self.data, self.headers, "POST", "https://example.com/inbox", "https://example.com/users/johndoe#main-key")

        is_valid = self.signer.verify(signature_header, normalized_data, self.headers)
        self.assertTrue(is_valid)

    def test_verify_invalid_signature(self):
        signature_header, normalized_data = self.signer.sign(self.data, self.headers, "POST", "https://example.com/inbox", "https://example.com/users/johndoe#main-key")

        signature_header['signature'] = 'invalid_signature'

        is_valid = self.signer.verify(signature_header, normalized_data, self.headers)
        self.assertFalse(is_valid)

if __name__ == '__main__':
    unittest.main()
