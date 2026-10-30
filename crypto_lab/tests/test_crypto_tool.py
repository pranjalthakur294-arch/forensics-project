"""
test_crypto_tool.py - Automated Unit & Security Tests for Crypto Lab (V1 & V2 Hardened)
Tests:
- Correct encryption/decryption round-trip for Version 1 and Version 2
- AES-GCM Additional Authenticated Data (AAD) tamper detection on V2 header
- Version 1 backward-compatible decryption
- Wrong password failure (IntegrityError, no unauthenticated plaintext leak)
- Tampered ciphertext & tag detection
- Corrupted/truncated file detection
- 0-byte empty file handling
- Evidence custody metadata generation & hash verification
- HMAC evidence authenticity signing & verification
- File overwrite safety checks (prevent clobbering without force)
- Large file streaming encryption & decryption
"""

import os
import sys
import unittest
import tempfile
import shutil

# Ensure crypto_lab is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CRYPTO_LAB_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if CRYPTO_LAB_DIR not in sys.path:
    sys.path.insert(0, CRYPTO_LAB_DIR)

from crypto_tool import (
    encrypt_file,
    decrypt_file,
    compute_sha256,
    generate_evidence_report,
    verify_integrity,
    benchmark_kdf,
    IntegrityError,
    DecryptionError,
    VERSION_1,
    VERSION_2,
)


class TestCryptoTool(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="forensics_crypto_test_")
        self.sample_text = "Forensic chain-of-custody test string. Secret data."
        self.sample_file = os.path.join(self.test_dir, "sample.txt")
        with open(self.sample_file, "w", encoding="utf-8") as f:
            f.write(self.sample_text)
        self.password = "ForensicsSecurePass2026!"

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_encrypt_decrypt_roundtrip_v2_default(self):
        """Test default Version 2 authenticated encryption with header AAD."""
        enc_file = os.path.join(self.test_dir, "sample_v2.enc")
        dec_file = os.path.join(self.test_dir, "sample_v2_rec.txt")

        meta = encrypt_file(
            self.sample_file,
            output_path=enc_file,
            password=self.password,
            iterations=10_000,
            version=VERSION_2,
            generate_evidence=True,
        )

        self.assertEqual(meta["format_version"], VERSION_2)
        self.assertTrue(os.path.exists(enc_file))
        self.assertTrue(os.path.exists(enc_file + ".evidence.txt"))

        # Decrypt V2 (auto-discovers iterations from header)
        recovered_path = decrypt_file(
            enc_file,
            output_path=dec_file,
            password=self.password,
        )

        with open(recovered_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), self.sample_text)
        self.assertEqual(compute_sha256(recovered_path), compute_sha256(self.sample_file))

    def test_v1_backward_compatibility(self):
        """Test Version 1 legacy format encryption and backward-compatible decryption."""
        enc_v1 = os.path.join(self.test_dir, "sample_v1.enc")
        dec_v1 = os.path.join(self.test_dir, "sample_v1_rec.txt")

        meta = encrypt_file(
            self.sample_file,
            output_path=enc_v1,
            password=self.password,
            iterations=10_000,
            version=VERSION_1,
        )
        self.assertEqual(meta["format_version"], VERSION_1)

        # Decrypt V1
        recovered_path = decrypt_file(
            enc_v1,
            output_path=dec_v1,
            password=self.password,
            expected_iterations=10_000,
        )

        with open(recovered_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), self.sample_text)

    def test_v2_aad_header_tamper_detection(self):
        """Test that altering any header byte in V2 (version, iterations) triggers GCM tag failure."""
        enc_file = os.path.join(self.test_dir, "sample_tamper.enc")
        dec_file = os.path.join(self.test_dir, "sample_tamper_rec.txt")

        encrypt_file(
            self.sample_file,
            output_path=enc_file,
            password=self.password,
            iterations=10_000,
            version=VERSION_2,
        )

        # Tamper byte 10 (part of the 4-byte iteration field in V2 header)
        with open(enc_file, "r+b") as f:
            f.seek(10)
            orig = f.read(1)[0]
            f.seek(10)
            f.write(bytes([orig ^ 0x01]))

        with self.assertRaises(IntegrityError):
            decrypt_file(enc_file, output_path=dec_file, password=self.password)

        self.assertFalse(os.path.exists(dec_file))

    def test_wrong_password_fails_and_leaves_no_artifact(self):
        """Test decryption with an incorrect password raises IntegrityError and wipes temp file."""
        enc_file = os.path.join(self.test_dir, "sample.txt.enc")
        dec_file = os.path.join(self.test_dir, "sample_recovered.txt")

        encrypt_file(
            self.sample_file,
            output_path=enc_file,
            password=self.password,
            iterations=10_000,
        )

        with self.assertRaises(IntegrityError):
            decrypt_file(
                enc_file,
                output_path=dec_file,
                password="WrongPassword123!",
            )

        self.assertFalse(os.path.exists(dec_file))
        self.assertFalse(os.path.exists(dec_file + ".tmp"))

    def test_tampered_ciphertext_fails(self):
        """Test that altering a single byte in ciphertext triggers an integrity error."""
        enc_file = os.path.join(self.test_dir, "sample.txt.enc")
        dec_file = os.path.join(self.test_dir, "sample_recovered.txt")

        encrypt_file(
            self.sample_file,
            output_path=enc_file,
            password=self.password,
            iterations=10_000,
        )

        with open(enc_file, "r+b") as f:
            f.seek(45)
            original_byte = f.read(1)[0]
            f.seek(45)
            f.write(bytes([original_byte ^ 0xFF]))

        with self.assertRaises(IntegrityError):
            decrypt_file(enc_file, output_path=dec_file, password=self.password)

        self.assertFalse(os.path.exists(dec_file))

    def test_tampered_tag_fails(self):
        """Test modifying trailing 16-byte GCM authentication tag causes verification failure."""
        enc_file = os.path.join(self.test_dir, "sample.txt.enc")
        dec_file = os.path.join(self.test_dir, "sample_recovered.txt")

        encrypt_file(
            self.sample_file,
            output_path=enc_file,
            password=self.password,
            iterations=10_000,
        )

        size = os.path.getsize(enc_file)
        with open(enc_file, "r+b") as f:
            f.seek(size - 1)
            b = f.read(1)[0]
            f.seek(size - 1)
            f.write(bytes([b ^ 0x01]))

        with self.assertRaises(IntegrityError):
            decrypt_file(enc_file, output_path=dec_file, password=self.password)

    def test_truncated_header_raises_decryption_error(self):
        """Test that truncated file or invalid magic bytes raises DecryptionError."""
        bad_file = os.path.join(self.test_dir, "corrupted.enc")
        with open(bad_file, "wb") as f:
            f.write(b"CORRUPT_HEADER_TOO_SHORT")

        with self.assertRaises(DecryptionError):
            decrypt_file(bad_file, password="any")

    def test_overwrite_safety_check(self):
        """Test that attempting to overwrite an existing file raises FileExistsError without force."""
        enc_file = os.path.join(self.test_dir, "sample.txt.enc")
        encrypt_file(self.sample_file, output_path=enc_file, password=self.password, iterations=5_000)

        # Attempt to overwrite without force (in non-tty)
        with self.assertRaises(FileExistsError):
            encrypt_file(self.sample_file, output_path=enc_file, password=self.password, iterations=5_000, force=False)

        # Overwrite with force=True succeeds
        meta = encrypt_file(self.sample_file, output_path=enc_file, password=self.password, iterations=5_000, force=True)
        self.assertTrue(os.path.exists(enc_file))

    def test_hmac_evidence_authenticity(self):
        """Test generating HMAC authenticity signature for evidence report and verifying it."""
        hmac_key = "InvestigatorSecretHmacKey2026!"
        ev_file = generate_evidence_report(self.sample_file, hmac_key=hmac_key)
        self.assertTrue(os.path.exists(ev_file))

        # Verification with valid key succeeds
        valid, msg = verify_integrity(self.sample_file, ev_file, hmac_key=hmac_key)
        self.assertTrue(valid)
        self.assertIn("Authenticity verified via HMAC", msg)

        # Verification with wrong HMAC key fails authenticity
        valid, msg = verify_integrity(self.sample_file, ev_file, hmac_key="WrongHmacKey!")
        self.assertFalse(valid)
        self.assertIn("authenticity verification failed", msg)

        # Tampering with evidence report text triggers authenticity failure
        with open(ev_file, "a", encoding="utf-8") as f:
            f.write("forged_line: true\n")
        valid, msg = verify_integrity(self.sample_file, ev_file, hmac_key=hmac_key)
        self.assertFalse(valid)

    def test_empty_file_roundtrip(self):
        """Test encrypting and decrypting a 0-byte file in V2 format."""
        empty_file = os.path.join(self.test_dir, "empty.txt")
        open(empty_file, "wb").close()
        enc_file = empty_file + ".enc"
        dec_file = empty_file + ".rec"

        encrypt_file(empty_file, output_path=enc_file, password="EmptyPassword!", iterations=2_000, version=VERSION_2)
        # 41 header bytes + 16 tag bytes = 57 bytes in V2
        self.assertEqual(os.path.getsize(enc_file), 57)

        decrypt_file(enc_file, output_path=dec_file, password="EmptyPassword!")
        self.assertEqual(os.path.getsize(dec_file), 0)

    def test_verify_legacy_evidence_format(self):
        """Test verify_integrity against legacy evidence files containing only sha256_plaintext:."""
        legacy_ev = os.path.join(self.test_dir, "legacy.evidence.txt")
        actual_sha = compute_sha256(self.sample_file)
        with open(legacy_ev, "w", encoding="utf-8") as f:
            f.write(f"original_file: sample.txt\nsha256_plaintext: {actual_sha}\npbkdf2_iterations: 200000\n")

        valid, _ = verify_integrity(self.sample_file, legacy_ev)
        self.assertTrue(valid)

    def test_iteration_minimum_validation(self):
        """Test that derive_key rejects iterations below 1000."""
        from crypto_tool import derive_key
        with self.assertRaises(ValueError):
            derive_key("password", b"1" * 16, iterations=500)

    def test_password_env_resolution(self):
        """Test resolving password from an environment variable."""
        from crypto_tool import resolve_password
        os.environ["TEST_ENV_KEY"] = "EnvPassSecret2026!"
        resolved = resolve_password(env_var="TEST_ENV_KEY")
        self.assertEqual(resolved, "EnvPassSecret2026!")
        del os.environ["TEST_ENV_KEY"]

        with self.assertRaises(ValueError):
            resolve_password(env_var="NONEXISTENT_VAR_FORENSICS")

    def test_large_file_streaming(self):
        """Test encrypting and decrypting a large (2 MB) file without errors."""
        large_file = os.path.join(self.test_dir, "large.bin")
        large_enc = os.path.join(self.test_dir, "large.bin.enc")
        large_dec = os.path.join(self.test_dir, "large_rec.bin")

        pattern = b"A" * 1024 + b"B" * 1024
        with open(large_file, "wb") as f:
            for _ in range(1024):
                f.write(pattern)

        orig_hash = compute_sha256(large_file)
        encrypt_file(large_file, output_path=large_enc, password="LargeFileTestPassword!", iterations=5_000)
        decrypt_file(large_enc, output_path=large_dec, password="LargeFileTestPassword!")
        self.assertEqual(compute_sha256(large_dec), orig_hash)

    def test_benchmark_kdf_runs(self):
        """Test benchmark_kdf execution returns benchmark rows."""
        res = benchmark_kdf(iterations_list=[10_000, 20_000])
        self.assertEqual(len(res), 2)
        self.assertGreater(res[0][2], 0)


if __name__ == "__main__":
    unittest.main()
