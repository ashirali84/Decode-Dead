
import unittest

from modules.jwt.decoder import decode_jwt
from modules.jwt.inspector import inspect_decoded_jwt


class TestJWTIntegration(unittest.TestCase):

    def test_decode_then_inspect_claims(self):
        # Header: {"alg":"HS256","typ":"JWT"}
        # Payload: {"sub":"ashir","exp":4102444800}
        token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiJhc2hpc iIsImV4cCI6NDEwMjQ0NDgwMH0."
            "c2lnbmF0dXJl"
        ).replace(" ", "")

        decoded = decode_jwt(token)

        self.assertTrue(decoded["valid_structure"])

        inspection = inspect_decoded_jwt(decoded)

        self.assertEqual(
            inspection["standard_claims"]["sub"]["value"],
            "ashir",
        )
        self.assertEqual(
            inspection["time_claims"]["exp"]["status"],
            "Not expired",
        )
        self.assertFalse(inspection["signature_verified"])

    def test_reject_invalid_structure(self):
        decoded = {
            "valid_structure": False,
            "payload": {},
        }

        with self.assertRaises(ValueError):
            inspect_decoded_jwt(decoded)


if __name__ == "__main__":
    unittest.main()