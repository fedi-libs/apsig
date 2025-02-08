import unittest

from cryptography.hazmat.primitives.asymmetric import ed25519

from apsig import KeyUtil

class TestSignatureFunctions(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.private_key = ed25519.Ed25519PrivateKey.generate()
        cls.public_key = cls.private_key.public_key()
        cls.public_raw = cls.public_key.public_bytes_raw()
        cls.kutil = KeyUtil(private_key=cls.private_key)

    def test_encode(self):
        result = self.kutil.encode_multibase()
        if result:
            success = True
        else:
            success = False
        self.assertTrue(success)

    def test_decode(self):
        multibase = self.kutil.encode_multibase()
        result = self.kutil.decode_multibase(multibase)
        if result:
            success = True
        else:
            success = False

        self.assertTrue(success)

if __name__ == '__main__':
    unittest.main()
