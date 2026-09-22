
import base64
import unittest
import zlib

from flask.json.tag import TaggedJSONSerializer

from modules.flask_cookie.decoder import decode_cookie_payload


def make_cookie(payload, compressed=False):
    raw = TaggedJSONSerializer().dumps(payload).encode("utf-8")

    if compressed:
        raw = zlib.compress(raw)

    encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")

    if compressed:
        encoded = "." + encoded

    # Dummy timestamp and signature for decoder testing only.
    return f"{encoded}.MTIzNDU2.signature"


class TestFlaskCookieDecoder(unittest.TestCase):

    def test_decode_simple_payload(self):
        cookie = make_cookie({"user": "ashir"})

        result = decode_cookie_payload(cookie)

        self.assertEqual(
            result["payload"]["user"],
            "ashir",
        )
        self.assertFalse(result["signature_verified"])

    def test_decode_compressed_payload(self):
        cookie = make_cookie(
            {"user": "ashir", "role": "guest"},
            compressed=True,
        )

        result = decode_cookie_payload(cookie)

        self.assertTrue(result["compressed"])
        self.assertEqual(
            result["payload"]["role"],
            "guest",
        )

    def test_reject_empty_cookie(self):
        with self.assertRaises(ValueError):
            decode_cookie_payload("")

    def test_reject_wrong_segment_count(self):
        with self.assertRaises(ValueError):
            decode_cookie_payload("one.two")

    def test_reject_invalid_payload(self):
        with self.assertRaises(ValueError):
            decode_cookie_payload("%%% .timestamp.signature")


if __name__ == "__main__":
    unittest.main()