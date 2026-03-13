import os
import socket
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# --- Configuration ---
KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537
PORT = 12345
ROLE = os.environ.get("ROLE", "server")
TARGET_IP = os.environ.get("TARGET_IP")
SENDER_NAME = os.environ.get("SENDER", "default_sender")

# --- Utility Functions ---
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT, key_size=KEY_SIZE
    )
    return private_key, private_key.public_key()

def serialize_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def deserialize_key(key_bytes):
    return serialization.load_pem_public_key(key_bytes)

def encrypt(message, public_key):
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def decrypt(ciphertext, private_key):
    try:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        ).decode()
    except Exception:
        return "DECRYPTION_FAILED"

def truncate(data, length=30):
    """Truncates bytes for clean printing."""
    return str(data[:length]) + "..." if len(data) > length else str(data)

# --- Network Logic ---
def handle_connection(conn, private_key, my_public_key):
    """Generic handler for both client and server after connection."""
    print(f"[{SENDER_NAME}] Connection established. Exchanging keys...")
    
    # 1. Exchange public keys
    conn.sendall(serialize_key(my_public_key))
    print(f"[{SENDER_NAME}] -> Sent public key.")
    
    their_public_key_bytes = conn.recv(2048)
    their_public_key = deserialize_key(their_public_key_bytes)
    print(f"[{SENDER_NAME}] <- Received peer's public key.")

    # 2. Communication loop
    message_count = 0
    while True:
        if ROLE == 'client':
            # Clients initiate the conversation
            message = f"Hello from {SENDER_NAME}, message #{message_count}"
            encrypted_message = encrypt(message, their_public_key)
            print(f"[{SENDER_NAME}] -> Sending: '{message}' (encrypted: {truncate(encrypted_message)})")
            conn.sendall(encrypted_message)
            
            encrypted_ack = conn.recv(2048)
            if not encrypted_ack: break
            decrypted_ack = decrypt(encrypted_ack, private_key)
            print(f"[{SENDER_NAME}] <- Received ack: '{decrypted_ack}' (encrypted: {truncate(encrypted_ack)})")
            
            message_count += 1
            time.sleep(3)
        else: # Server
            # Servers respond
            encrypted_message = conn.recv(2048)
            if not encrypted_message: break
            decrypted_message = decrypt(encrypted_message, private_key)
            print(f"[{SENDER_NAME}] <- Received: '{decrypted_message}' (encrypted: {truncate(encrypted_message)})")

            ack_message = f"Ack from {SENDER_NAME}"
            encrypted_ack = encrypt(ack_message, their_public_key)
            print(f"[{SENDER_NAME}] -> Sending ack: '{ack_message}' (encrypted: {truncate(encrypted_ack)})")
            conn.sendall(encrypted_ack)

def run_server(private_key, public_key):
    """Server listens for one connection."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", PORT))
        s.listen()
        print(f"[{SENDER_NAME}] Server listening on port {PORT}...")
        conn, addr = s.accept()
        with conn:
            handle_connection(conn, private_key, public_key)

def run_client(private_key, public_key):
    """Client connects to the target."""
    time.sleep(5) # Give server/proxy time to start
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[{SENDER_NAME}] Client connecting to {TARGET_IP}:{PORT}...")
        s.connect((TARGET_IP, PORT))
        handle_connection(s, private_key, public_key)

def main():
    """Main function to generate keys and start client or server."""
    print(f"--- [{SENDER_NAME.upper()}] ---")
    private_key, public_key = generate_keys()
    print(f"[{SENDER_NAME}] Generated RSA key pair.")

    if ROLE == "server":
        run_server(private_key, public_key)
    elif ROLE == "client":
        run_client(private_key, public_key)
    print(f"[{SENDER_NAME}] Shutting down.")

if __name__ == "__main__":
    main()
