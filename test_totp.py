from utils_crypto import generate_totp_code, verify_totp_code

hex_seed = "5b2d3c01f92552b0c75d7ac23fa6134bb5b32152f96e74c8638fd30ccf9f3d2f"

code = generate_totp_code(hex_seed)
print("Generated TOTP:", code)

print("Verify:", verify_totp_code(hex_seed, code))
