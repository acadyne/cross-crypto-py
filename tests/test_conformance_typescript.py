from __future__ import annotations

import json
import unittest
from pathlib import Path

from cross_crypto_py import (
    decrypt_ccenc_bytes,
    decrypt_json,
    key_id_from_public_key,
    verify_json,
)


FIXTURES = Path(__file__).with_name("fixtures")


def text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def load_json(name: str):
    return json.loads(text(name))


class TypeScriptConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = load_json("manifest.json")
        cls.rsa_private = text("rsa_private.pem")
        cls.rsa_public = text("rsa_public.pem")
        cls.ed_public = text("ed25519_public.pem")

    def test_shared_spki_kids(self) -> None:
        self.assertEqual(
            key_id_from_public_key(self.rsa_public),
            self.manifest["rsaKid"],
        )
        self.assertEqual(
            key_id_from_public_key(self.ed_public),
            self.manifest["ed25519Kid"],
        )

    def test_decrypts_typescript_jwe(self) -> None:
        value = decrypt_json(
            load_json("typescript_jwe.json"),
            self.rsa_private,
            expected_key_id=self.manifest["rsaKid"],
            expected_aad=self.manifest["aad"],
        )
        self.assertEqual(value, self.manifest["payload"])

    def test_verifies_typescript_jws(self) -> None:
        value = verify_json(
            load_json("typescript_jws.json"),
            self.ed_public,
            expected_key_id=self.manifest["ed25519Kid"],
        )
        self.assertEqual(value, self.manifest["payload"])

    def test_decrypts_typescript_ccenc(self) -> None:
        encrypted = (FIXTURES / "typescript_ccenc.bin").read_bytes()
        expected = (FIXTURES / "ccenc_plain.bin").read_bytes()
        result = decrypt_ccenc_bytes(
            encrypted,
            self.rsa_private,
            expected_key_id=self.manifest["rsaKid"],
        )
        self.assertEqual(result["plaintext"], expected)


if __name__ == "__main__":
    unittest.main()
