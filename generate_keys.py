from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_rsa_keypair(key_size: int = 4096):
    """
    Generate RSA key pair
    
    Returns:
        Tuple of (private_key, public_key) objects
    """
    # 1. Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # 2. Serialize private key (PEM format)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1 format
        encryption_algorithm=serialization.NoEncryption()
    )

    # 3. Serialize public key (PEM format)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


if __name__ == "__main__":
    private_pem, public_pem = generate_rsa_keypair()

    # Save private key
    with open("student_private.pem", "wb") as f:
        f.write(private_pem)

    # Save public key
    with open("student_public.pem", "wb") as f:
        f.write(public_pem)

    print("Generated student_private.pem and student_public.pem")
