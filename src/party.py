import base64
import hashlib
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class Party:
    def __init__(self, name: str) -> None:
        self.name = name
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.nonce = None
        self.session_key = None

    def generate_nonce(self) -> int:
        self.nonce = random.randint(0, 10**9)
        return self.nonce

    def generate_session_key(self) -> bytes:
        self.session_key = Fernet.generate_key()
        return self.session_key

    def apply_hashing(self, text: str, hashing_function=hashlib.sha256) -> str:
        return hashing_function(text.encode("utf-8")).hexdigest()

    def apply_encryption(self, text: str, encryption_function) -> str:
        return encryption_function(text)

    def apply_decryption(self, text: str, decryption_function) -> str:
        return decryption_function(text)

    def combine_hash_and_message(self, message: str, message_hash: str) -> str:
        return f"{message_hash}{message}"

    def split_hash_and_message(self, combined_message: str, hash_length: int) -> tuple[str, str]:
        extracted_hash = combined_message[:hash_length]
        extracted_message = combined_message[hash_length:]
        return extracted_hash, extracted_message

    def push_message_to_queue(self, message: str, queue_obj) -> None:
        if hasattr(queue_obj, "put"):
            queue_obj.put(message)
            return
        if hasattr(queue_obj, "append"):
            queue_obj.append(message)
            return
        raise TypeError("Queue object must support put() or append().")

    def pop_message_from_queue(self, queue_obj) -> str:
        if hasattr(queue_obj, "get"):
            return queue_obj.get()
        if hasattr(queue_obj, "pop"):
            return queue_obj.pop(0)
        raise TypeError("Queue object must support get() or pop(index).")

    def encrypt_with_public_key(self, public_key, plaintext: str) -> str:
        encrypted = public_key.encrypt(
            plaintext.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return base64.b64encode(encrypted).decode("utf-8")

    def decrypt_with_private_key(self, ciphertext_b64: str) -> str:
        ciphertext = base64.b64decode(ciphertext_b64.encode("utf-8"))
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext.decode("utf-8")

    def encrypt_with_private_key(self, plaintext: str) -> str:
        message_bytes = plaintext.encode("utf-8")
        n = self.private_key.private_numbers().public_numbers.n
        d = self.private_key.private_numbers().d
        key_bytes = (n.bit_length() + 7) // 8

        if len(message_bytes) >= key_bytes:
            raise ValueError("Plaintext too long for raw RSA demo operation.")

        message_int = int.from_bytes(message_bytes, byteorder="big")
        encrypted_int = pow(message_int, d, n)
        encrypted_bytes = encrypted_int.to_bytes(key_bytes, byteorder="big")
        return base64.b64encode(encrypted_bytes).decode("utf-8")

    def decrypt_with_public_key(self, ciphertext_b64: str, public_key) -> str:
        encrypted_bytes = base64.b64decode(ciphertext_b64.encode("utf-8"))
        public_numbers = public_key.public_numbers()
        n = public_numbers.n
        e = public_numbers.e
        key_bytes = (n.bit_length() + 7) // 8

        if len(encrypted_bytes) != key_bytes:
            raise ValueError("Invalid ciphertext length for raw RSA demo operation.")

        encrypted_int = int.from_bytes(encrypted_bytes, byteorder="big")
        decrypted_int = pow(encrypted_int, e, n)
        decrypted_bytes = decrypted_int.to_bytes(key_bytes, byteorder="big").lstrip(b"\x00")
        return decrypted_bytes.decode("utf-8")

    def encrypt_with_session_key(self, plaintext: str, session_key: bytes | None = None) -> str:
        key = session_key or self.session_key
        if key is None:
            raise ValueError("No session key available. Generate or provide one first.")
        cipher = Fernet(key)
        token = cipher.encrypt(plaintext.encode("utf-8"))
        return token.decode("utf-8")

    def decrypt_with_session_key(self, ciphertext: str, session_key: bytes | None = None) -> str:
        key = session_key or self.session_key
        if key is None:
            raise ValueError("No session key available. Generate or provide one first.")
        cipher = Fernet(key)
        plaintext = cipher.decrypt(ciphertext.encode("utf-8"))
        return plaintext.decode("utf-8")
