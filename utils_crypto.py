import base64
import binascii
import pyotp
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


# -----------------------------------------------------------
# STEP 5: LOAD PRIVATE KEY
# -----------------------------------------------------------
def load_private_key(path: str):
    """
    Load RSA private key from PEM file.
    """
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )


# -----------------------------------------------------------
# STEP 5: RSA/OAEP-SEED DECRYPTION
# -----------------------------------------------------------
def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP (SHA-256).

    Returns:
        64-character lowercase hex seed string.
    """
    # 1. Base64 decode
    try:
        ciphertext = base64.b64decode(encrypted_seed_b64)
    except Exception as e:
        raise ValueError("Invalid base64 input") from e

    # 2. RSA OAEP-SHA256 decryption
    try:
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError("Decryption failed") from e

    # 3. Decode UTF-8
    try:
        seed_str = plaintext_bytes.decode("utf-8").strip()
    except Exception as e:
        raise ValueError("Decrypted seed is not valid UTF-8 text") from e

    # 4. Validate hex seed
    seed = seed_str.lower()

    if len(seed) != 64:
        raise ValueError("Seed must be exactly 64 hex characters")

    allowed = set("0123456789abcdef")
    if any(c not in allowed for c in seed):
        raise ValueError("Seed contains non-hex characters")

    return seed


# -----------------------------------------------------------
# STEP 6: HEX → BASE32 CONVERSION
# -----------------------------------------------------------
def hex_to_base32(hex_seed: str) -> str:
    """
    Convert 64-character hex seed into base32.
    Required by TOTP.
    """
    seed_bytes = bytes.fromhex(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode("utf-8")
    return base32_seed


# -----------------------------------------------------------
# STEP 6: GENERATE TOTP CODE (SHA-1, 30s, 6 digits)
# -----------------------------------------------------------
def generate_totp_code(hex_seed: str) -> str:
    """
    Generate a 6-digit TOTP code based on 64-char hex seed.
    """
    base32_seed = hex_to_base32(hex_seed)

    totp = pyotp.TOTP(
        base32_seed,
        digits=6,
        interval=30  # 30-second window
    )

    return totp.now()


# -----------------------------------------------------------
# STEP 6: VERIFY TOTP CODE (±1 TIME WINDOW)
# -----------------------------------------------------------
def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a TOTP code with ± valid_window periods (±30 seconds).
    """
    base32_seed = hex_to_base32(hex_seed)

    totp = pyotp.TOTP(
        base32_seed,
        digits=6,
        interval=30
    )

    return totp.verify(code, valid_window=valid_window)
