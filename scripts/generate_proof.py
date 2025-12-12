#!/usr/bin/env python3
"""
Generate commit proof:
1) Get latest commit hash (40-char hex)
2) Sign it with student_private.pem using RSA-PSS (SHA-256, MGF1, max salt)
3) Encrypt signature with instructor_public.pem using RSA/OAEP (SHA-256, MGF1)
4) Base64 encode encrypted signature and print single-line output

Usage:
    python3 scripts/generate_proof.py
"""

import subprocess
import sys
import base64
import re
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.backends import default_backend

# Paths (adjust if your files are elsewhere)
STUDENT_PRIVATE_PATH = Path("student_private.pem")
INSTRUCTOR_PUBLIC_PATH = Path("instructor_public.pem")


def load_private_key(path: Path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def load_public_key(path: Path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def sign_message(message: str, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Sign message (ASCII string) using RSA-PSS with SHA-256 and maximum salt length.
    Returns raw signature bytes.
    """
    if not isinstance(message, str):
        raise TypeError("message must be str")

    message_bytes = message.encode("utf-8")  # SIGN ASCII/UTF-8
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def encrypt_with_public_key(data: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    Encrypt data bytes using RSA OAEP (SHA-256, MGF1(SHA-256)).
    Returns ciphertext bytes.
    """
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def get_latest_commit_hash() -> str:
    """
    Get the latest commit hash from local git.
    Returns 40-char hex string.
    """
    try:
        out = subprocess.check_output(["git", "log", "-1", "--format=%H"], stderr=subprocess.STDOUT)
        commit_hash = out.decode("utf-8").strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to get git commit hash: {e.output.decode('utf-8', errors='ignore')}")

    if not re.fullmatch(r"[0-9a-fA-F]{40}", commit_hash):
        raise ValueError(f"Commit hash is not a 40-character hex string: {commit_hash!r}")

    return commit_hash


def main():
    # 0. Sanity: files exist
    if not STUDENT_PRIVATE_PATH.exists():
        print(f"ERROR: {STUDENT_PRIVATE_PATH} not found. Please run from repository root and ensure file exists.", file=sys.stderr)
        sys.exit(2)
    if not INSTRUCTOR_PUBLIC_PATH.exists():
        print(f"ERROR: {INSTRUCTOR_PUBLIC_PATH} not found.", file=sys.stderr)
        sys.exit(2)

    # 1. Get commit hash
    commit_hash = get_latest_commit_hash()
    print("Commit Hash:", commit_hash)

    # 2. Load keys
    private_key = load_private_key(STUDENT_PRIVATE_PATH)
    instructor_pub = load_public_key(INSTRUCTOR_PUBLIC_PATH)

    # 3. Sign commit hash (ASCII)
    try:
        signature = sign_message(commit_hash, private_key)
    except Exception as e:
        print("ERROR: signing failed:", e, file=sys.stderr)
        sys.exit(3)

    # 4. Encrypt signature with instructor public key
    try:
        encrypted = encrypt_with_public_key(signature, instructor_pub)
    except Exception as e:
        print("ERROR: encryption failed:", e, file=sys.stderr)
        sys.exit(4)

    # 5. Base64 encode the encrypted signature (single line)
    encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")
    print("\nEncrypted Signature (base64, single line):")
    print(encrypted_b64)

    # Optionally save to file
    out_path = Path("encrypted_signature.txt")
    out_path.write_text(encrypted_b64)
    print(f"\nSaved base64 encrypted signature to: {out_path}")

    # Exit success
    sys.exit(0)


if __name__ == "__main__":
    main()
