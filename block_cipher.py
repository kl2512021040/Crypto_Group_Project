# block_cipher.py
# Implementation of AES-128 in Galois Counter Mode (GCM)
# Provides both confidentiality and authentication (AEAD)

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypts plaintext using AES-128 GCM mode.
    Returns: (ciphertext, nonce, tag)
    """
    # GCM automatically generates a unique 16-byte nonce if not provided
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, nonce, tag

def decrypt_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypts ciphertext and verifies its integrity using AES-128 GCM mode.
    Raises ValueError if tag verification fails (data tampered).
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

# --- Verification & Testing ---
if __name__ == "__main__":
    test_message = "Cryptography"
    
    # AES-128 requires exactly 16 bytes (128 bits) key length
    # Using 16 bytes secret key
    secret_key = b"rahsiakuncinwc11"

    plaintext_bytes = test_message.encode('utf-8')

    # Encryption Process
    ciphertext, nonce, tag = encrypt_aes_gcm(plaintext_bytes, secret_key)

    # Decryption & Integrity Verification Process
    try:
        decrypted_bytes = decrypt_aes_gcm(ciphertext, secret_key, nonce, tag)
        decrypted_message = decrypted_bytes.decode('utf-8')
        status = "Successful Decryption & Tag Verified!"
    except ValueError:
        decrypted_message = "ERROR"
        status = "Decryption Failed: Data or Tag Tampered!"

    # Display results
    print("=== AES-128 GCM BLOCK CIPHER TEST ===")
    print(f"Plaintext        : {test_message}")
    print(f"Key (ASCII)      : {secret_key.decode('utf-8')}")
    print(f"Nonce (Hex)      : {nonce.hex()}")
    print(f"Auth Tag (Hex)   : {tag.hex()}")
    print(f"Ciphertext (Hex) : {ciphertext.hex()}")
    print(f"Decrypted Text   : {decrypted_message}")
    print(f"Status           : {status}")

    # Correctness Assertion
    assert decrypted_message == test_message, "Decryption failed!"
    