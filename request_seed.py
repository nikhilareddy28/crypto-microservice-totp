import requests
import json

def request_seed(student_id: str, github_repo_url: str, api_url: str):
    """
    Request encrypted seed from instructor API.
    """
    # Step 1: Read public key
    with open("student_public.pem", "r") as f:
        public_key_pem = f.read()

    # Step 2: Prepare payload
    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key_pem  # JSON library will handle newlines correctly
    }

    # Step 3: Send POST request
    response = requests.post(api_url, json=payload, timeout=20)

    # Step 4: Validate and extract encrypted seed
    data = response.json()
    print("API Response:", data)

    if data.get("status") != "success" or "encrypted_seed" not in data:
        raise Exception("Failed to get encrypted seed from API.")

    encrypted_seed = data["encrypted_seed"]

    # Step 5: Save encrypted seed to file
    with open("encrypted_seed.txt", "w") as f:
        f.write(encrypted_seed)

    print("Encrypted seed saved to encrypted_seed.txt")


if __name__ == "__main__":
    # >>> UPDATE THIS <<<
    STUDENT_ID = "23P31A0547"  # Replace with your real student ID
    
    GITHUB_REPO_URL = "https://github.com/nikhilareddy28/crypto-microservice-totp"
    
    API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"

    request_seed(STUDENT_ID, GITHUB_REPO_URL, API_URL)
