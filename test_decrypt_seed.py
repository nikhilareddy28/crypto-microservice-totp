from utils_crypto import decrypt_seed, load_private_key

private_key = load_private_key("student_private.pem")

with open("encrypted_seed.txt", "r") as f:
    encrypted = f.read().strip()

hex_seed = decrypt_seed(encrypted, private_key)
print("Decrypted seed:", hex_seed)
