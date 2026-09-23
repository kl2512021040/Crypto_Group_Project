# stream_cipher.py
# Implementation of a Simplified RC4-like Stream Cipher using XOR mechanism

def generate_keystream(key: bytes, length: int) -> bytes:
    """
    Generates a keystream by repeating the key bytes until it reaches the desired length.
    """
    keystream = bytearray()
    key_length = len(key)
    for i in range(length):
        keystream.append(key[i % key_length])
    return bytes(keystream)

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypts plaintext bytes using XOR operation with generated keystream.
    """
    keystream = generate_keystream(key, len(plaintext))
    ciphertext = bytearray()
    for p, k in zip(plaintext, keystream):
        ciphertext.append(p ^ k)
    return bytes(ciphertext)

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypts ciphertext bytes using XOR operation with generated keystream.
    (XOR encryption is symmetric, so decryption uses the exact same process)
    """
    return encrypt(ciphertext, key)

# --- Verification & Testing ---
if __name__ == "__main__":
    test_message = "Cryptography"
    secret_key = "KEY"

    # Convert strings to bytes
    plaintext_bytes = test_message.encode('utf-8')
    key_bytes = secret_key.encode('utf-8')

    # Encryption
    ciphertext_bytes = encrypt(plaintext_bytes, key_bytes)
    
    # Decryption
    decrypted_bytes = decrypt(ciphertext_bytes, key_bytes)
    decrypted_message = decrypted_bytes.decode('utf-8')

    # Display results
    print("=== STREAM CIPHER TEST ===")
    print(f"Plaintext        : {test_message}")
    print(f"Key              : {secret_key}")
    print(f"Ciphertext (Hex) : {ciphertext_bytes.hex()}")
    print(f"Decrypted Text   : {decrypted_message}")
    
    # Correctness Assertion
    assert decrypted_message == test_message, "Decryption failed!"
    print("Status           : Successful Decryption!")