import json
import unittest

import cross_crypto_py as cc
from cross_crypto_py.encoding import b64url_decode, b64url_encode


class ProtocolV3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rsa = cc.generate_rsa_key_pair(2048)
        cls.ed = cc.generate_ed25519_key_pair()

    def test_jwe_json_roundtrip_and_aad(self) -> None:
        value = {"hello": "mundo", "unicode": "🌊", "n": 42}
        envelope = cc.encrypt_json(value, self.rsa["public_key"], aad="route:/test")
        self.assertEqual(
            cc.decrypt_json(
                envelope,
                self.rsa["private_key"],
                expected_key_id=self.rsa["kid"],
                expected_aad="route:/test",
            ),
            value,
        )

        wrong_kid = b64url_encode(bytes(32))
        with self.assertRaises(cc.CrossCryptoError) as key_error:
            cc.encrypt_json(value, self.rsa["public_key"], key_id=wrong_kid)
        self.assertEqual(key_error.exception.code, "key_mismatch")

        with self.assertRaises(cc.CrossCryptoError) as aad_limit:
            cc.encrypt_json(
                value,
                self.rsa["public_key"],
                aad=bytes(64 * 1024 + 1),
            )
        self.assertEqual(aad_limit.exception.code, "payload_too_large")

        tampered = dict(envelope)
        tag = tampered["tag"]
        tampered["tag"] = tag[:-1] + ("A" if tag[-1] != "A" else "B")
        with self.assertRaises(cc.CrossCryptoError):
            cc.decrypt_json(tampered, self.rsa["private_key"])

        with self.assertRaises(cc.CrossCryptoError) as aad_error:
            cc.decrypt_json(
                envelope,
                self.rsa["private_key"],
                expected_aad="route:/other",
            )
        self.assertEqual(aad_error.exception.code, "authentication_failed")

        protected_header = json.loads(
            b64url_decode(envelope["protected"]).decode("utf-8")
        )
        protected_header["kid"] = b64url_encode(bytes(32))
        header_tampered = dict(envelope)
        header_tampered["protected"] = b64url_encode(
            json.dumps(protected_header, separators=(",", ":")).encode("utf-8")
        )
        with self.assertRaises(cc.CrossCryptoError) as header_error:
            cc.decrypt_json(header_tampered, self.rsa["private_key"])
        self.assertEqual(header_error.exception.code, "authentication_failed")

    def test_jws_protects_iat_and_kid(self) -> None:
        value = {"action": "transfer", "amount": 10}
        envelope = cc.sign_json(
            value,
            self.ed["private_key"],
            key_id=self.ed["kid"],
            signed_at=1000,
            expires_at=2000,
        )
        self.assertEqual(
            cc.verify_json(
                envelope,
                self.ed["public_key"],
                expected_key_id=self.ed["kid"],
                now=1500,
            ),
            value,
        )

        wrong_kid = b64url_encode(bytes(32))
        wrong_kid_envelope = cc.sign_json(
            value,
            self.ed["private_key"],
            key_id=wrong_kid,
            signed_at=1000,
            expires_at=2000,
        )
        with self.assertRaises(cc.CrossCryptoError) as time_error:
            cc.sign_json(
                value,
                self.ed["private_key"],
                key_id=self.ed["kid"],
                signed_at=9_007_199_254_740_992,
            )
        self.assertEqual(time_error.exception.code, "invalid_format")
        with self.assertRaises(cc.CrossCryptoError) as key_error:
            cc.verify_json(wrong_kid_envelope, self.ed["public_key"], now=1500)
        self.assertEqual(key_error.exception.code, "key_mismatch")

        header = json.loads(b64url_decode(envelope["protected"]).decode("utf-8"))
        header["iat"] = 1500
        tampered = dict(envelope)
        tampered["protected"] = b64url_encode(
            json.dumps(header, separators=(",", ":")).encode("utf-8")
        )
        self.assertFalse(
            cc.is_valid_signature(tampered, self.ed["public_key"], now=1500)
        )
        with self.assertRaises(cc.CrossCryptoError) as signature_error:
            cc.verify_json(tampered, self.ed["public_key"], now=1500)
        self.assertEqual(signature_error.exception.code, "signature_invalid")

        with self.assertRaises(cc.CrossCryptoError) as expired:
            cc.verify_json(
                envelope,
                self.ed["public_key"],
                now=1501,
                max_age_seconds=100,
            )
        self.assertEqual(expired.exception.code, "expired")

    def test_ccenc_multichunk_and_tamper(self) -> None:
        data = bytes(i % 251 for i in range(150_000))
        encrypted = cc.encrypt_ccenc_bytes(
            data,
            self.rsa["public_key"],
            chunk_size=65_536,
            name="fixture.bin",
        )
        with self.assertRaises(cc.CrossCryptoError) as key_error:
            cc.encrypt_ccenc_bytes(
                data,
                self.rsa["public_key"],
                key_id=b64url_encode(bytes(32)),
                chunk_size=65_536,
            )
        self.assertEqual(key_error.exception.code, "key_mismatch")
        result = cc.decrypt_ccenc_bytes(
            encrypted,
            self.rsa["private_key"],
            expected_key_id=self.rsa["kid"],
            expected_name="fixture.bin",
        )
        self.assertEqual(result["plaintext"], data)
        self.assertEqual(result["header"]["ccv"], 3)

        tampered = bytearray(encrypted)
        tampered[-1] ^= 1
        with self.assertRaises(cc.CrossCryptoError):
            cc.decrypt_ccenc_bytes(tampered, self.rsa["private_key"])

        with self.assertRaises(cc.CrossCryptoError):
            cc.decrypt_ccenc_bytes(encrypted + b"\\x01", self.rsa["private_key"])

        with self.assertRaises(cc.CrossCryptoError):
            cc.encrypt_ccenc_bytes(
                data,
                self.rsa["public_key"],
                chunk_size=65_536,
                name="../unsafe.bin",
            )


    def test_binary_empty_and_payload_limits(self) -> None:
        samples = [b"", b"\x00\xff\x80binary\x00"]
        for sample in samples:
            envelope = cc.encrypt_bytes(sample, self.rsa["public_key"])
            result = cc.decrypt_bytes(
                envelope,
                self.rsa["private_key"],
                expected_key_id=self.rsa["kid"],
            )
            self.assertEqual(result["plaintext"], sample)

        envelope = cc.encrypt_bytes(b"0123456789", self.rsa["public_key"])
        with self.assertRaises(cc.CrossCryptoError) as too_large:
            cc.decrypt_bytes(
                envelope,
                self.rsa["private_key"],
                max_payload_bytes=1,
            )
        self.assertEqual(too_large.exception.code, "payload_too_large")

    def test_strict_base64url_and_wrong_keys(self) -> None:
        envelope = cc.encrypt_bytes(b"secret", self.rsa["public_key"])
        malformed = dict(envelope)
        malformed["iv"] = malformed["iv"] + "="
        with self.assertRaises(cc.CrossCryptoError) as encoding_error:
            cc.decrypt_bytes(malformed, self.rsa["private_key"])
        self.assertEqual(encoding_error.exception.code, "invalid_encoding")

        wrong_rsa = cc.generate_rsa_key_pair(2048)
        with self.assertRaises(cc.CrossCryptoError) as decrypt_error:
            cc.decrypt_bytes(envelope, wrong_rsa["private_key"])
        self.assertEqual(decrypt_error.exception.code, "authentication_failed")

        signed = cc.sign_bytes(
            b"payload",
            self.ed["private_key"],
            key_id=self.ed["kid"],
            signed_at=1000,
        )
        wrong_ed = cc.generate_ed25519_key_pair()
        with self.assertRaises(cc.CrossCryptoError) as verify_error:
            cc.verify_bytes(signed, wrong_ed["public_key"], now=1000)
        self.assertEqual(verify_error.exception.code, "signature_invalid")

    def test_key_generation_rejects_weak_rsa(self) -> None:
        with self.assertRaises(cc.CrossCryptoError) as weak:
            cc.generate_rsa_key_pair(1024)
        self.assertEqual(weak.exception.code, "invalid_key")



    def test_json_domain_rejects_ambiguous_or_unsafe_values(self) -> None:
        bad_values = [
            float("nan"),
            float("inf"),
            -float("inf"),
            9_007_199_254_740_992,
            {"bad": 9_007_199_254_740_992},
            {1: "non-string-key"},
            ("tuple",),
            {"bad": "\ud800"},
        ]
        for value in bad_values:
            with self.subTest(value=repr(value)):
                with self.assertRaises(cc.CrossCryptoError) as error:
                    cc.encrypt_json(value, self.rsa["public_key"])
                self.assertIn(error.exception.code, {"invalid_format", "payload_too_large"})

        deep = current = {}
        for _ in range(66):
            child = {}
            current["x"] = child
            current = child
        with self.assertRaises(cc.CrossCryptoError) as depth_error:
            cc.encrypt_json(deep, self.rsa["public_key"])
        self.assertEqual(depth_error.exception.code, "invalid_format")



if __name__ == "__main__":
    unittest.main()
