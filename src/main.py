import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# --- Configuration ---
SHARED_DIR = "shared"
KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537
SENDER = os.environ.get("SENDER", "alice")
RECEIVER = os.environ.get("RECEIVER", "bob")


def generate_keys():
    """Generates a new RSA private and public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_key(key, filename):
    """Saves a key to a file."""
    with open(filename, "wb") as f:
        if isinstance(key, rsa.RSAPrivateKey):
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        else:
            f.write(
                key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )


def load_key(filename, private=False):
    """Loads a key from a file."""
    with open(filename, "rb") as f:
        if private:
            return serialization.load_pem_private_key(f.read(), password=None)
        else:
            return serialization.load_pem_public_key(f.read())


def encrypt(message, public_key):
    """Encrypts a message using a public key."""
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt(ciphertext, private_key):
    """Decrypts a message using a private key."""
    try:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        ).decode()
    except Exception as e:
        return f"Decryption failed: {e}"


def main():
    """Main function to run the communication simulation."""
    sender_private_key_file = os.path.join(SHARED_DIR, f"{SENDER}_private.pem")
    sender_public_key_file = os.path.join(SHARED_DIR, f"{SENDER}_public.pem")
    receiver_public_key_file = os.path.join(SHARED_DIR, f"{RECEIVER}_public.pem")

    # Create shared directory if it doesn't exist
    os.makedirs(SHARED_DIR, exist_ok=True)

    # Generate and save sender's keys if they don't exist
    if not os.path.exists(sender_private_key_file):
        print(f"[{SENDER}] Generating keys...")
        private_key, public_key = generate_keys()
        save_key(private_key, sender_private_key_file)
        save_key(public_key, sender_public_key_file)
        print(f"[{SENDER}] Keys generated and saved.")
    else:
        print(f"[{SENDER}] Keys already exist.")

    private_key = load_key(sender_private_key_file, private=True)

    # Wait for receiver's public key
    print(f"[{SENDER}] Waiting for {RECEIVER}'s public key...")
    while not os.path.exists(receiver_public_key_file):
        time.sleep(1)
    print(f"[{SENDER}] {RECEIVER}'s public key found.")
    receiver_public_key = load_key(receiver_public_key_file)

    # Communication loop
    message_count = 0
    while True:
        # Send a message
        message = f"Hello {RECEIVER}, this is {SENDER}. Message #{message_count}"
        print(f"[{SENDER}] Sending: {message}")
        encrypted_message = encrypt(message, receiver_public_key)

        message_file = os.path.join(SHARED_DIR, f"{RECEIVER}.msg")
        with open(message_file, "wb") as f:
            f.write(encrypted_message)

        message_count += 1

        # Check for incoming messages
        my_message_file = os.path.join(SHARED_DIR, f"{SENDER}.msg")
        if os.path.exists(my_message_file):
            with open(my_message_file, "rb") as f:
                ciphertext = f.read()
            decrypted_message = decrypt(ciphertext, private_key)
            print(f"[{SENDER}] Received: {decrypted_message}")
            os.remove(my_message_file)

        time.sleep(1)


if __name__ == "__main__":
    main()
