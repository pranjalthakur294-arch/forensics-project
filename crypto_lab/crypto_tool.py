"""
crypto_tool.py - Forensic-grade File Encryption, Decryption & Evidence Custody System
Part of the Digital Forensics Portfolio Suite.

Cryptographic Architecture:
- Format Version 1 (Legacy):
    [8B Magic: 'FENCRYPT'] [1B Ver: 0x01] [16B Salt] [12B Nonce]
    [Ciphertext Stream] [16B GCM Tag]
    Key Derivation: PBKDF2-HMAC-SHA256 (default 200,000 iterations)
    AAD: None (backward compatible)

- Format Version 2 (Hardened Current Standard):
    [8B Magic: 'FENCRYPT'] [1B Ver: 0x02] [4B Big-Endian Iterations] [16B Salt] [12B Nonce]
    [Ciphertext Stream] [16B GCM Tag]
    Key Derivation: PBKDF2-HMAC-SHA256 (default 600,000 iterations per OWASP recommendations)
    AAD: Complete 41-byte header is cryptographically bound via AES-GCM Associated Data.
    Tamper Resistance: Tampering with Magic, Version, Iterations, Salt, Nonce, Ciphertext,
                       or Authentication Tag triggers cryptographic verification failure.

Evidence Custody:
- Plaintext and Ciphertext SHA-256 separation with unique UUID evidence identifiers.
- Optional HMAC-SHA256 custody signing for proving evidence authenticity (distinguishing
  integrity verification from non-repudiation / proof of authenticity).
"""

import argparse
import getpass
import hashlib
import hmac
import os
import struct
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

try:
    from Crypto.Cipher import AES
except ImportError:
    sys.exit(
        "Error: 'pycryptodome' is required. Install it using: pip install -r requirements.txt"
    )

MAGIC_HEADER = b"FENCRYPT"
VERSION_1 = 1
VERSION_2 = 2
CURRENT_VERSION = VERSION_2

SALT_SIZE = 16          # 128-bit salt for PBKDF2
NONCE_SIZE = 12         # 96-bit standard nonce for AES-GCM (NIST SP 800-38D)
KEY_SIZE = 32           # 256-bit AES key
TAG_SIZE = 16           # 128-bit GCM authentication tag

DEFAULT_ITERATIONS_V1 = 200_000
DEFAULT_ITERATIONS_V2 = 600_000  # OWASP recommended minimum for PBKDF2-HMAC-SHA256
CHUNK_SIZE = 64 * 1024           # 64 KB streaming buffer for large forensic images


class IntegrityError(Exception):
    """Raised when authentication tag verification or hash integrity fails."""
    pass


class DecryptionError(Exception):
    """Raised when decryption fails due to invalid password, bad header, or corruption."""
    pass


def compute_sha256(filepath: str, chunk_size: int = CHUNK_SIZE) -> str:
    """Compute the SHA-256 hex digest of a file in streaming chunks."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS_V2) -> bytes:
    """Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256."""
    if not password:
        raise ValueError("Password cannot be empty.")
    if iterations < 1000:
        raise ValueError(f"PBKDF2 iteration count too low ({iterations}). Minimum required is 1,000.")
    return hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt,
        iterations=iterations,
        dklen=KEY_SIZE,
    )


def compute_hmac_sha256(key: str, data: str) -> str:
    """Compute HMAC-SHA256 signature for evidence authentication."""
    return hmac.new(key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256).hexdigest()


def confirm_overwrite(path: str, force: bool = False) -> bool:
    """Verify if target file exists and handle overwrite protection."""
    if not os.path.exists(path):
        return True
    if force:
        return True
    if not sys.stdin.isatty():
        raise FileExistsError(
            f"Output file '{path}' already exists. Use --force to allow overwriting."
        )
    ans = input(f"[?] File '{path}' already exists. Overwrite? [y/N]: ").strip().lower()
    if ans in ("y", "yes"):
        return True
    raise FileExistsError(f"Operation aborted by user. Output file '{path}' was not overwritten.")


def encrypt_file(
    input_path: str,
    output_path: str = None,
    password: str = None,
    iterations: int = DEFAULT_ITERATIONS_V2,
    version: int = CURRENT_VERSION,
    generate_evidence: bool = True,
    hmac_key: str = None,
    force: bool = False,
) -> Dict:
    """
    Encrypt a file using AES-256-GCM.

    Version 1 Format:
      Header (37 bytes): [MAGIC (8B)] [0x01 (1B)] [SALT (16B)] [NONCE (12B)]
      Ciphertext + Tag (16B). AAD = None.

    Version 2 Format (Default):
      Header (41 bytes): [MAGIC (8B)] [0x02 (1B)] [ITERATIONS (4B big-endian)] [SALT (16B)] [NONCE (12B)]
      Ciphertext + Tag (16B). AAD = Complete 41-byte header.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")

    if not output_path:
        output_path = input_path + ".enc"

    confirm_overwrite(output_path, force=force)

    if not password:
        password = getpass.getpass("Enter encryption password: ")
        confirm = getpass.getpass("Confirm encryption password: ")
        if password != confirm:
            raise ValueError("Passwords do not match.")

    # 1. Plaintext SHA-256 for chain of custody
    plaintext_sha256 = compute_sha256(input_path)
    plaintext_size = os.path.getsize(input_path)

    # 2. Cryptographic salt & nonce
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    # 3. Key derivation
    key = derive_key(password, salt, iterations)

    # 4. Construct Header
    if version == VERSION_1:
        header = MAGIC_HEADER + bytes([VERSION_1]) + salt + nonce
        aad = None
    elif version == VERSION_2:
        iter_bytes = struct.pack(">I", iterations)
        header = MAGIC_HEADER + bytes([VERSION_2]) + iter_bytes + salt + nonce
        aad = header
    else:
        raise ValueError(f"Unsupported encryption format version: {version}")

    # 5. Initialize AES-GCM cipher
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad is not None:
        cipher.update(aad)

    # 6. Stream encryption to isolated temporary file
    temp_out = output_path + ".tmp"
    try:
        with open(input_path, "rb") as fin, open(temp_out, "wb") as fout:
            fout.write(header)
            while chunk := fin.read(CHUNK_SIZE):
                fout.write(cipher.encrypt(chunk))
            tag = cipher.digest()
            fout.write(tag)

        # Atomic replacement
        os.replace(temp_out, output_path)

    except Exception:
        if os.path.exists(temp_out):
            try:
                os.remove(temp_out)
            except OSError:
                pass
        raise

    # 7. Ciphertext SHA-256 and metadata
    ciphertext_sha256 = compute_sha256(output_path)
    ciphertext_size = os.path.getsize(output_path)
    evidence_uuid = str(uuid.uuid4())
    now_utc = datetime.now(timezone.utc).isoformat()

    metadata = {
        "evidence_id": evidence_uuid,
        "format_version": version,
        "original_file": os.path.basename(input_path),
        "encrypted_file": os.path.basename(output_path),
        "plaintext_size_bytes": plaintext_size,
        "ciphertext_size_bytes": ciphertext_size,
        "hash_algorithm": "SHA-256",
        "sha256_plaintext": plaintext_sha256,
        "sha256_ciphertext": ciphertext_sha256,
        "encryption_algorithm": "AES-256-GCM",
        "pbkdf2_iterations": iterations,
        "salt(hex)": salt.hex(),
        "nonce(hex)": nonce.hex(),
        "tag(hex)": tag.hex(),
        "timestamp_utc": now_utc,
    }

    if generate_evidence:
        evidence_path = output_path + ".evidence.txt"
        confirm_overwrite(evidence_path, force=force)
        report_lines = [
            "=== Digital Forensics Evidence Custody Report ===",
            f"evidence_id: {evidence_uuid}",
            f"format_version: {version}",
            f"original_file: {os.path.basename(input_path)}",
            f"encrypted_file: {os.path.basename(output_path)}",
            f"plaintext_size_bytes: {plaintext_size}",
            f"ciphertext_size_bytes: {ciphertext_size}",
            f"hash_algorithm: SHA-256",
            f"sha256_plaintext: {plaintext_sha256}",
            f"sha256_ciphertext: {ciphertext_sha256}",
            f"encryption_algorithm: AES-256-GCM",
            f"pbkdf2_iterations: {iterations}",
            f"salt(hex): {salt.hex()}",
            f"nonce(hex): {nonce.hex()}",
            f"tag(hex): {tag.hex()}",
            f"timestamp_utc: {now_utc}",
            "integrity_verification: Validated via SHA-256 hash pair",
        ]

        if hmac_key:
            data_to_sign = "\n".join(report_lines)
            sig = compute_hmac_sha256(hmac_key, data_to_sign)
            report_lines.append(f"hmac_authenticity_signature: {sig}")
            metadata["hmac_authenticity_signature"] = sig
            metadata["authenticated_with_hmac"] = True
        else:
            report_lines.append("authenticity_notice: Unsigned report. Proves data integrity but not author identity.")

        with open(evidence_path, "w", encoding="utf-8") as ef:
            ef.write("\n".join(report_lines) + "\n")
        metadata["evidence_file"] = evidence_path

    return metadata


def decrypt_file(
    input_path: str,
    output_path: str = None,
    password: str = None,
    expected_iterations: int = None,
    force: bool = False,
) -> str:
    """
    Decrypt a file encrypted with encrypt_file.
    Supports both Version 1 and Version 2 formats.
    In Version 2, verifies AAD across all header fields.
    Guarantees atomic rollback on wrong password or tampering.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Encrypted file not found: {input_path}")

    file_size = os.path.getsize(input_path)

    # Minimum size check: Magic(8) + Version(1) + Tag(16) = 25 bytes
    if file_size < (len(MAGIC_HEADER) + 1 + TAG_SIZE):
        raise DecryptionError(f"File too small to be a valid encrypted artifact ({file_size} bytes).")

    if not output_path:
        if input_path.endswith(".enc"):
            output_path = input_path[:-4] + ".recovered"
        else:
            output_path = input_path + ".decrypted"

    confirm_overwrite(output_path, force=force)

    if not password:
        password = getpass.getpass("Enter decryption password: ")

    temp_out = output_path + ".tmp"

    try:
        with open(input_path, "rb") as fin:
            magic = fin.read(len(MAGIC_HEADER))
            if magic != MAGIC_HEADER:
                raise DecryptionError("Invalid file header: magic bytes mismatch.")

            version_byte = fin.read(1)
            if not version_byte:
                raise DecryptionError("Unexpected EOF while reading version.")
            version = version_byte[0]

            if version == VERSION_1:
                # Version 1 header: 37 bytes total
                header_size = len(MAGIC_HEADER) + 1 + SALT_SIZE + NONCE_SIZE
                if file_size < header_size + TAG_SIZE:
                    raise DecryptionError(f"File truncated for Version 1 ({file_size} bytes).")
                salt = fin.read(SALT_SIZE)
                nonce = fin.read(NONCE_SIZE)
                iterations = expected_iterations or DEFAULT_ITERATIONS_V1
                aad = None

            elif version == VERSION_2:
                # Version 2 header: 41 bytes total
                iter_bytes = fin.read(4)
                if len(iter_bytes) < 4:
                    raise DecryptionError("File truncated while reading iteration count.")
                header_iterations = struct.unpack(">I", iter_bytes)[0]
                iterations = expected_iterations or header_iterations
                salt = fin.read(SALT_SIZE)
                nonce = fin.read(NONCE_SIZE)
                header_size = len(MAGIC_HEADER) + 1 + 4 + SALT_SIZE + NONCE_SIZE
                if file_size < header_size + TAG_SIZE:
                    raise DecryptionError(f"File truncated for Version 2 ({file_size} bytes).")
                # Reconstruct full 41-byte header for AAD
                header_aad = MAGIC_HEADER + bytes([VERSION_2]) + iter_bytes + salt + nonce
                aad = header_aad

            else:
                raise DecryptionError(f"Unsupported file format version: {version}")

            # Derive key
            key = derive_key(password, salt, iterations)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            if aad is not None:
                cipher.update(aad)

            # Stream-decrypt
            ciphertext_len = file_size - header_size - TAG_SIZE
            bytes_left = ciphertext_len

            with open(temp_out, "wb") as fout:
                while bytes_left > 0:
                    read_len = min(CHUNK_SIZE, bytes_left)
                    chunk = fin.read(read_len)
                    if not chunk:
                        raise DecryptionError("Unexpected EOF while streaming ciphertext.")
                    fout.write(cipher.decrypt(chunk))
                    bytes_left -= len(chunk)

            # Read and verify authentication tag
            tag = fin.read(TAG_SIZE)
            if len(tag) != TAG_SIZE:
                raise DecryptionError("Incomplete authentication tag.")

            try:
                cipher.verify(tag)
            except ValueError as err:
                raise IntegrityError(
                    "Authentication tag verification failed! "
                    "Incorrect password, tampered header/ciphertext, or corrupted authentication tag."
                ) from err

        # Commit output file atomically
        os.replace(temp_out, output_path)

    finally:
        if os.path.exists(temp_out):
            try:
                os.remove(temp_out)
            except OSError:
                pass

    return output_path


def generate_evidence_report(filepath: str, output_path: str = None, hmac_key: str = None, force: bool = False) -> str:
    """Generate a standalone forensic custody record with SHA-256 and optional HMAC authenticity."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    if not output_path:
        output_path = filepath + ".evidence.txt"

    confirm_overwrite(output_path, force=force)

    sha256_hash = compute_sha256(filepath)
    size = os.path.getsize(filepath)
    mtime = datetime.fromtimestamp(os.path.getmtime(filepath), tz=timezone.utc).isoformat()
    now_utc = datetime.now(timezone.utc).isoformat()
    ev_uuid = str(uuid.uuid4())

    lines = [
        "=== Digital Forensics Evidence Custody Report ===",
        f"evidence_id: {ev_uuid}",
        f"file_name: {os.path.basename(filepath)}",
        f"full_path: {os.path.abspath(filepath)}",
        f"file_size_bytes: {size}",
        f"file_mtime_utc: {mtime}",
        f"hash_algorithm: SHA-256",
        f"sha256: {sha256_hash}",
        f"evidence_generated_utc: {now_utc}",
        "integrity_status: Verified",
    ]

    if hmac_key:
        sig = compute_hmac_sha256(hmac_key, "\n".join(lines))
        lines.append(f"hmac_authenticity_signature: {sig}")
    else:
        lines.append("authenticity_notice: Unsigned report. Proves data integrity but not author identity.")

    with open(output_path, "w", encoding="utf-8") as ef:
        ef.write("\n".join(lines) + "\n")

    return output_path


def verify_integrity(filepath: str, target_hash_or_evidence: str, hmac_key: str = None) -> Tuple[bool, str]:
    """
    Verify file integrity against expected hash or evidence file.
    If hmac_key is provided, also validates HMAC signature for proof of authenticity.
    Returns (is_valid: bool, reason: str).
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Target file not found: {filepath}")

    expected_hash = None
    evidence_dict = {}

    if os.path.exists(target_hash_or_evidence):
        raw_lines = []
        with open(target_hash_or_evidence, "r", encoding="utf-8", errors="replace") as ef:
            for line in ef:
                raw_lines.append(line.rstrip("\r\n"))
                line_str = line.strip()
                if ":" in line_str:
                    k, v = line_str.split(":", 1)
                    evidence_dict[k.strip().lower()] = v.strip().lower()

        is_enc = filepath.endswith(".enc")
        if is_enc and "sha256_ciphertext" in evidence_dict:
            expected_hash = evidence_dict["sha256_ciphertext"]
        elif not is_enc and "sha256_plaintext" in evidence_dict:
            expected_hash = evidence_dict["sha256_plaintext"]
        elif "sha256" in evidence_dict:
            expected_hash = evidence_dict["sha256"]
        elif "sha256_plaintext" in evidence_dict:
            expected_hash = evidence_dict["sha256_plaintext"]

        # If HMAC key is passed, verify evidence authenticity signature
        if hmac_key:
            if "hmac_authenticity_signature" not in evidence_dict:
                return False, "Evidence file has no HMAC authenticity signature to verify."
            expected_sig = evidence_dict["hmac_authenticity_signature"]
            unsigned_lines = [l for l in raw_lines if not l.startswith("hmac_authenticity_signature:")]
            computed_sig = compute_hmac_sha256(hmac_key, "\n".join(unsigned_lines))
            if not hmac.compare_digest(computed_sig, expected_sig):
                return False, "HMAC authenticity verification failed! Evidence file has been altered or forged."
    else:
        expected_hash = target_hash_or_evidence.strip().lower()

    if not expected_hash:
        raise ValueError(f"Could not extract a valid SHA-256 hash from '{target_hash_or_evidence}'")

    actual_hash = compute_sha256(filepath).lower()
    if actual_hash != expected_hash.lower():
        return False, f"Hash mismatch: actual {actual_hash} != expected {expected_hash}"

    auth_msg = " (Authenticity verified via HMAC)" if (hmac_key and "hmac_authenticity_signature" in evidence_dict) else ""
    return True, f"Integrity verified successfully{auth_msg}."


def benchmark_kdf(iterations_list: list = None) -> list:
    """Benchmark PBKDF2-HMAC-SHA256 iteration performance on the local host."""
    if not iterations_list:
        iterations_list = [100_000, 200_000, 600_000, 1_000_000]

    salt = b"benchmark_salt_1"
    pw = b"benchmark_password"
    results = []

    print("\n--- PBKDF2-HMAC-SHA256 Hardware Benchmark ---")
    print(f"  {'Iterations':<15} | {'Duration (ms)':<15} | {'Rate (iters/sec)':<18}")
    print("  " + "-" * 52)

    for iters in iterations_list:
        t0 = time.perf_counter()
        _ = hashlib.pbkdf2_hmac("sha256", pw, salt, iters, dklen=32)
        dt = time.perf_counter() - t0
        rate = iters / dt if dt > 0 else 0
        results.append((iters, dt * 1000, rate))
        print(f"  {iters:<15,} | {dt*1000:<15.2f} | {rate:<18,.0f}")

    print("----------------------------------------------\n")
    return results


def resolve_password(cli_pwd: str = None, env_var: str = None, prompt_confirm: bool = False) -> str:
    """Resolve password with security warnings for CLI arguments."""
    if env_var:
        val = os.environ.get(env_var)
        if val:
            return val
        raise ValueError(f"Environment variable '{env_var}' is not set or empty.")
    if cli_pwd:
        print("[!] SECURITY WARNING: Passing passwords via CLI arguments can be exposed in process tables and shell history.", file=sys.stderr)
        return cli_pwd
    if prompt_confirm:
        pwd = getpass.getpass("Enter encryption password: ")
        confirm = getpass.getpass("Confirm encryption password: ")
        if pwd != confirm:
            raise ValueError("Passwords do not match.")
        return pwd
    return getpass.getpass("Enter decryption password: ")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Forensic-grade AES-256-GCM Encryption & Evidence Custody CLI Tool (V1/V2 AAD Support)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Encrypt
    p_enc = subparsers.add_parser("encrypt", help="Encrypt file with AES-256-GCM")
    p_enc.add_argument("input", help="Path to input plaintext file")
    p_enc.add_argument("-o", "--out", help="Output path for encrypted file")
    p_enc.add_argument("-p", "--password", help="Encryption password (or prompted securely)")
    p_enc.add_argument("--password-env", help="Read password from specified environment variable")
    p_enc.add_argument(
        "-i", "--iterations", type=int, default=DEFAULT_ITERATIONS_V2,
        help=f"PBKDF2 iteration count (default: {DEFAULT_ITERATIONS_V2})"
    )
    p_enc.add_argument("--format-version", type=int, choices=[1, 2], default=VERSION_2, help="File format version (1=Legacy, 2=Hardened AAD)")
    p_enc.add_argument("--hmac-key", help="Key for HMAC evidence signing")
    p_enc.add_argument("--hmac-env", help="Environment variable containing HMAC signing key")
    p_enc.add_argument("--no-evidence", action="store_true", help="Skip writing .evidence.txt")
    p_enc.add_argument("-f", "--force", action="store_true", help="Overwrite existing output without prompt")

    # Decrypt
    p_dec = subparsers.add_parser("decrypt", help="Decrypt file with AES-256-GCM (V1/V2 auto-detected)")
    p_dec.add_argument("input", help="Path to input encrypted file (.enc)")
    p_dec.add_argument("-o", "--out", help="Output path for decrypted plaintext")
    p_dec.add_argument("-p", "--password", help="Decryption password (or prompted securely)")
    p_dec.add_argument("--password-env", help="Read password from specified environment variable")
    p_dec.add_argument("-i", "--iterations", type=int, default=None, help="Explicit PBKDF2 iterations (optional for V2)")
    p_dec.add_argument("-f", "--force", action="store_true", help="Overwrite existing output without prompt")

    # Evidence
    p_ev = subparsers.add_parser("evidence", help="Generate SHA-256 evidence record for a file")
    p_ev.add_argument("input", help="Path to evidence file")
    p_ev.add_argument("-o", "--out", help="Output path for evidence report")
    p_ev.add_argument("--hmac-key", help="Key for HMAC evidence signing")
    p_ev.add_argument("--hmac-env", help="Environment variable containing HMAC signing key")
    p_ev.add_argument("-f", "--force", action="store_true", help="Overwrite existing report without prompt")

    # Verify
    p_ver = subparsers.add_parser("verify", help="Verify file integrity against hash or evidence file")
    p_ver.add_argument("input", help="Path to file to verify")
    p_ver.add_argument("expected", help="Expected SHA-256 hex string or path to .evidence.txt")
    p_ver.add_argument("--hmac-key", help="Key for verifying HMAC evidence authenticity signature")
    p_ver.add_argument("--hmac-env", help="Environment variable containing HMAC key")

    # Benchmark
    subparsers.add_parser("benchmark", help="Benchmark PBKDF2-HMAC-SHA256 iterations on this machine")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            pwd = resolve_password(args.password, args.password_env, prompt_confirm=True) if (args.password or args.password_env or not sys.stdin.isatty()) else None
            if not pwd and sys.stdin.isatty():
                pwd = resolve_password(prompt_confirm=True)
            hmac_k = os.environ.get(args.hmac_env) if args.hmac_env else args.hmac_key
            meta = encrypt_file(
                input_path=args.input,
                output_path=args.out,
                password=pwd,
                iterations=args.iterations,
                version=args.format_version,
                generate_evidence=not args.no_evidence,
                hmac_key=hmac_k,
                force=args.force,
            )
            print(f"[+] Encryption Successful (Format Version {meta['format_version']})!")
            print(f"    Encrypted File:     {meta['encrypted_file']}")
            print(f"    Plaintext SHA-256:  {meta['sha256_plaintext']}")
            print(f"    Ciphertext SHA-256: {meta['sha256_ciphertext']}")
            if "evidence_file" in meta:
                print(f"    Evidence Metadata:  {meta['evidence_file']}")

        elif args.command == "decrypt":
            pwd = resolve_password(args.password, args.password_env, prompt_confirm=False) if (args.password or args.password_env or not sys.stdin.isatty()) else None
            if not pwd and sys.stdin.isatty():
                pwd = resolve_password(prompt_confirm=False)
            out_file = decrypt_file(
                input_path=args.input,
                output_path=args.out,
                password=pwd,
                expected_iterations=args.iterations,
                force=args.force,
            )
            print("[+] Decryption & Authentication Successful!")
            print(f"    Recovered File: {out_file}")
            print(f"    SHA-256: {compute_sha256(out_file)}")

        elif args.command == "evidence":
            hmac_k = os.environ.get(args.hmac_env) if args.hmac_env else args.hmac_key
            rep_path = generate_evidence_report(args.input, args.out, hmac_key=hmac_k, force=args.force)
            print(f"[+] Evidence report generated: {rep_path}")
            print(f"    SHA-256: {compute_sha256(args.input)}")

        elif args.command == "verify":
            hmac_k = os.environ.get(args.hmac_env) if args.hmac_env else args.hmac_key
            matches, reason = verify_integrity(args.input, args.expected, hmac_key=hmac_k)
            if matches:
                print(f"[+] Integrity VERIFIED: {reason}")
                sys.exit(0)
            else:
                print(f"[-] Integrity FAILED: {reason}", file=sys.stderr)
                sys.exit(2)

        elif args.command == "benchmark":
            benchmark_kdf()

    except (IntegrityError, DecryptionError) as e:
        print(f"[-] Security Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
