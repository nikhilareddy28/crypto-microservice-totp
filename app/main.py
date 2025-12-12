from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
import time
import os

from utils_crypto import (
    load_private_key,
    decrypt_seed,
    generate_totp_code,
    verify_totp_code
)

# ---------------------------------------------------------
# CONSTANTS & PATHS
# ---------------------------------------------------------

DATA_DIR = Path("/data")
SEED_FILE = DATA_DIR / "seed.txt"

PRIVATE_KEY_PATH = "student_private.pem"

# Load private key once at startup
try:
    PRIVATE_KEY = load_private_key(PRIVATE_KEY_PATH)
except Exception:
    PRIVATE_KEY = None

app = FastAPI()


# ---------------------------------------------------------
# REQUEST MODELS
# ---------------------------------------------------------

class DecryptSeedRequest(BaseModel):
    encrypted_seed: str


class VerifyRequest(BaseModel):
    code: str


# ---------------------------------------------------------
# ENDPOINT 1
# POST /decrypt-seed
# ---------------------------------------------------------

@app.post("/decrypt-seed")
async def decrypt_seed_endpoint(req: DecryptSeedRequest):
    if PRIVATE_KEY is None:
        raise HTTPException(status_code=500, detail={"error": "Private key not loaded"})

    try:
        hex_seed = decrypt_seed(req.encrypted_seed, PRIVATE_KEY)
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})

    # Ensure /data exists
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    try:
        with open(SEED_FILE, "w") as f:
            f.write(hex_seed)
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Failed to store seed"})

    return {"status": "ok"}


# ---------------------------------------------------------
# ENDPOINT 2
# GET /generate-2fa
# ---------------------------------------------------------

@app.get("/generate-2fa")
async def generate_2fa():
    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    try:
        with open(SEED_FILE, "r") as f:
            hex_seed = f.read().strip()

        # Generate TOTP code
        code = generate_totp_code(hex_seed)

        # Remaining seconds in current 30s window
        now = int(time.time())
        valid_for = 30 - (now % 30)

        return {
            "code": code,
            "valid_for": valid_for
        }

    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Failed to generate 2FA"})


# ---------------------------------------------------------
# ENDPOINT 3
# POST /verify-2fa
# ---------------------------------------------------------

@app.post("/verify-2fa")
async def verify_2fa(req: VerifyRequest):
    if not req.code:
        raise HTTPException(status_code=400, detail={"error": "Missing code"})

    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    try:
        with open(SEED_FILE, "r") as f:
            hex_seed = f.read().strip()

        # Verify with ±1 time window (±30 seconds)
        is_valid = verify_totp_code(hex_seed, req.code, valid_window=1)

        return {"valid": bool(is_valid)}

    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Verification failed"})


# ---------------------------------------------------------
# HEALTH CHECK (optional)
# ---------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}
