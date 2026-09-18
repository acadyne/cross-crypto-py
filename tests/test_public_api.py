from __future__ import annotations

import inspect
import unittest
from typing import get_args

import cross_crypto_py as cc


EXPECTED_EXPORTS = {
    "__version__",
    "CrossCryptoError",
    "CrossCryptoErrorCode",
    "PROTOCOL_VERSION",
    "JWE_ALG",
    "JWE_ENC",
    "JWE_TYP",
    "JWS_ALG",
    "JWS_TYP",
    "JweEnvelope",
    "JweProtectedHeader",
    "JwsEnvelope",
    "JwsProtectedHeader",
    "KeyPair",
    "RsaKeyPair",
    "Ed25519KeyPair",
    "DecryptResult",
    "VerifyResult",
    "CcencDecryptResult",
    "CcencHeader",
    "generate_rsa_key_pair",
    "generate_ed25519_key_pair",
    "key_id_from_public_key",
    "encrypt_ccenc_bytes",
    "decrypt_ccenc_bytes",
    "encrypt_file",
    "decrypt_file",
    "read_ccenc_header",
    "read_ccenc_file_header",
    "encrypt_bytes",
    "decrypt_bytes",
    "read_jwe_protected_header",
    "sign_bytes",
    "verify_bytes",
    "is_valid_signature",
    "read_jws_protected_header",
    "encrypt_json",
    "decrypt_json",
    "encrypt_text",
    "decrypt_text",
    "sign_json",
    "verify_json",
    "sign_text",
    "verify_text",
}

EXPECTED_ERROR_CODES = {
    "invalid_format",
    "invalid_encoding",
    "unsupported_algorithm",
    "unsupported_version",
    "invalid_key",
    "key_mismatch",
    "authentication_failed",
    "signature_invalid",
    "expired",
    "not_yet_valid",
    "payload_too_large",
    "runtime_unavailable",
}


def shape(function):
    result = []
    for parameter in inspect.signature(function).parameters.values():
        default = None if parameter.default is inspect.Parameter.empty else parameter.default
        result.append((parameter.name, parameter.kind.name, default))
    return result


class PublicApiContractTests(unittest.TestCase):
    def test_root_exports_are_frozen(self):
        self.assertEqual(set(cc.__all__), EXPECTED_EXPORTS)
        for name in EXPECTED_EXPORTS:
            self.assertTrue(hasattr(cc, name), name)

    def test_shared_function_shapes_are_frozen(self):
        self.assertEqual(
            shape(cc.generate_rsa_key_pair),
            [("bits", "POSITIONAL_OR_KEYWORD", 3072)],
        )
        self.assertEqual(shape(cc.generate_ed25519_key_pair), [])
        self.assertEqual(
            shape(cc.key_id_from_public_key),
            [("public_key_pem", "POSITIONAL_OR_KEYWORD", None)],
        )

        self.assertEqual(
            shape(cc.encrypt_bytes),
            [
                ("plaintext", "POSITIONAL_OR_KEYWORD", None),
                ("public_key_pem", "POSITIONAL_OR_KEYWORD", None),
                ("key_id", "KEYWORD_ONLY", None),
                ("content_type", "KEYWORD_ONLY", None),
                ("aad", "KEYWORD_ONLY", None),
            ],
        )
        self.assertEqual(
            shape(cc.decrypt_bytes),
            [
                ("envelope", "POSITIONAL_OR_KEYWORD", None),
                ("private_key_pem", "POSITIONAL_OR_KEYWORD", None),
                ("expected_key_id", "KEYWORD_ONLY", None),
                ("expected_content_type", "KEYWORD_ONLY", None),
                ("expected_aad", "KEYWORD_ONLY", None),
                ("max_payload_bytes", "KEYWORD_ONLY", 64 * 1024 * 1024),
            ],
        )
        self.assertEqual(
            shape(cc.sign_bytes),
            [
                ("payload", "POSITIONAL_OR_KEYWORD", None),
                ("private_key_pem", "POSITIONAL_OR_KEYWORD", None),
                ("key_id", "KEYWORD_ONLY", None),
                ("signed_at", "KEYWORD_ONLY", None),
                ("expires_at", "KEYWORD_ONLY", None),
                ("content_type", "KEYWORD_ONLY", None),
            ],
        )
        self.assertEqual(
            shape(cc.verify_bytes),
            [
                ("envelope", "POSITIONAL_OR_KEYWORD", None),
                ("public_key_pem", "POSITIONAL_OR_KEYWORD", None),
                ("expected_key_id", "KEYWORD_ONLY", None),
                ("expected_content_type", "KEYWORD_ONLY", None),
                ("max_age_seconds", "KEYWORD_ONLY", None),
                ("now", "KEYWORD_ONLY", None),
                ("future_skew_seconds", "KEYWORD_ONLY", 30),
                ("max_payload_bytes", "KEYWORD_ONLY", 64 * 1024 * 1024),
            ],
        )

    def test_error_code_contract_is_typed_and_frozen(self):
        self.assertEqual(set(get_args(cc.CrossCryptoErrorCode)), EXPECTED_ERROR_CODES)

    def test_key_pair_aliases_have_same_portable_shape(self):
        self.assertEqual(cc.KeyPair.__required_keys__, {"public_key", "private_key", "kid"})
        self.assertIs(cc.RsaKeyPair, cc.KeyPair)
        self.assertIs(cc.Ed25519KeyPair, cc.KeyPair)

    def test_ccenc_result_contract_is_plaintext_plus_header(self):
        self.assertEqual(cc.CcencDecryptResult.__required_keys__, {"plaintext", "header"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
