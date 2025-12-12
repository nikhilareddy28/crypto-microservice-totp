#!/usr/bin/env python3

import sys
sys.path.append("/app")  # FIX: allow cron to import utils_crypto

import datetime
from pathlib import Path
from utils_crypto import generate_totp_code

SEED_FILE = Path("/data/seed.txt")
LOG_FILE = Path("/cron/last_code.txt")


def main():
    # 1. Load seed
    if not SEED_FILE.exists():
        return  # Seed not yet decrypted

    try:
        hex_seed = SEED_FILE.read_text().strip()
    except Exception:
        return  # Cannot read seed file

    # 2. Generate TOTP code
    try:
        code = generate_totp_code(hex_seed)
    except Exception:
        return  # Cannot generate code

    # 3. UTC timestamp
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # 4. Append formatted output
    with open(LOG_FILE, "a") as log:
        log.write(f"{timestamp} - 2FA Code: {code}\n")


if __name__ == "__main__":
    main()
