
import unittest

from modules.jwt.inspector import (
    format_timestamp,
    inspect_claims,
)


class TestJWTInspector(unittest.TestCase):

    def test_expired_token(self):
        payload = {"exp": 1000}
        result = inspect_claims(payload, now=1000)

        self.assertEqual(
            result["time_claims"]["exp"]["status"],
            "Expired",
        )

    def test_not_expired_token(self):
        payload = {"exp": 2000}
        result = inspect_claims(payload, now=1000)

        self.assertEqual(
            result["time_claims"]["exp"]["status"],
            "Not expired",
        )

    def test_nbf_in_future(self):
        payload = {"nbf": 2000}
        result = inspect_claims(payload, now=1000)

        self.assertEqual(
            result["time_claims"]["nbf"]["status"],
            "Not yet valid",
        )

    def test_iat_in_future(self):
        payload = {"iat": 2000}
        result = inspect_claims(payload, now=1000)

        self.assertEqual(
            result["time_claims"]["iat"]["status"],
            "Issued in the future",
        )

    def test_standard_claims(self):
        payload = {
            "iss": "test-issuer",
            "sub": "user-123",
            "aud": "test-app",
        }
        result = inspect_claims(payload, now=1000)

        self.assertEqual(
            result["standard_claims"]["iss"]["value"],
            "test-issuer",
        )
        self.assertEqual(
            result["standard_claims"]["sub"]["value"],
            "user-123",
        )
        self.assertEqual(
            result["standard_claims"]["aud"]["value"],
            "test-app",
        )

    def test_missing_exp(self):
        result = inspect_claims({}, now=1000)

        self.assertFalse(
            result["time_claims"]["exp"]["present"]
        )

    def test_invalid_timestamp(self):
        result = inspect_claims(
            {"exp": "tomorrow"},
            now=1000,
        )

        self.assertEqual(
            result["time_claims"]["exp"]["status"],
            "Invalid value",
        )
        self.assertTrue(result["warnings"])

    def test_format_timestamp(self):
        self.assertEqual(
            format_timestamp(0),
            "1970-01-01 00:00:00 UTC",
        )


if __name__ == "__main__":
    unittest.main()