# performance_test.py
# Performance Evaluation for Stream Cipher vs AES-128 GCM
# Generates test files, measures execution time, prints table, and plots graphs.

import os
import time
import matplotlib.pyplot as plt

# Import custom modules developed in Part A
from stream_cipher import encrypt as stream_encrypt, decrypt as stream_decrypt
from block_cipher import encrypt_aes_gcm, decrypt_aes_gcm

def generate_test_file(filename: str, size_bytes: int):
    """Generates a dummy file filled with random bytes for testing."""
    with open(filename, 'wb') as f:
        f.write(os.urandom(size_bytes))

def run_performance_tests():
    # File size configurations (1 KB, 100 KB, 1 MB)
    file_configs = {
        "1 KB": (1024, "test_1kb.bin"),
        "100 KB": (102400, "test_100kb.bin"),
        "1 MB": (1048576, "test_1mb.bin")
    }

    # Secret Keys
    stream_key = b"KEY"
    aes_key = b"rahsiakuncinwc11"  # 16 bytes for AES-128

    # Dictionary to store benchmark timings
    results = {
        "1 KB": {},
        "100 KB": {},
        "1 MB": {}
    }

    print("=== STARTING PERFORMANCE EVALUATION ===")
    
    for label, (size, filename) in file_configs.items():
        print(f"\n[+] Generating {label} test file...")
        generate_test_file(filename, size)
        
        with open(filename, 'rb') as f:
            data = f.read()

        # 1. STREAM CIPHER BENCHMARK
        t_start = time.perf_counter()
        stream_cipher_text = stream_encrypt(data, stream_key)
        t_stream_enc = time.perf_counter() - t_start

        t_start = time.perf_counter()
        _ = stream_decrypt(stream_cipher_text, stream_key)
        t_stream_dec = time.perf_counter() - t_start

        # 2. AES-128 GCM BENCHMARK
        t_start = time.perf_counter()
        aes_cipher_text, nonce, tag = encrypt_aes_gcm(data, aes_key)
        t_aes_enc = time.perf_counter() - t_start

        t_start = time.perf_counter()
        _ = decrypt_aes_gcm(aes_cipher_text, aes_key, nonce, tag)
        t_aes_dec = time.perf_counter() - t_start

        # Save timings (in seconds)
        results[label] = {
            "Stream Enc": t_stream_enc,
            "Stream Dec": t_stream_dec,
            "AES Enc": t_aes_enc,
            "AES Dec": t_aes_dec
        }

        # Clean up temporary test binary file
        if os.path.exists(filename):
            os.remove(filename)

    # PRINT TABULATED RESULTS
    print("\n" + "="*70)
    print(f"{'File Size':<10} | {'Stream Enc(s)':<14} | {'Stream Dec(s)':<14} | {'AES Enc(s)':<12} | {'AES Dec(s)':<12}")
    print("="*70)
    for label in results:
        res = results[label]
        print(f"{label:<10} | {res['Stream Enc']:<14.6f} | {res['Stream Dec']:<14.6f} | {res['AES Enc']:<12.6f} | {res['AES Dec']:<12.6f}")
    print("="*70)

    # GENERATE GRAPHICAL COMPARISON
    plot_results(results)

def plot_results(results):
    labels = list(results.keys())
    stream_enc = [results[lbl]["Stream Enc"] for lbl in labels]
    stream_dec = [results[lbl]["Stream Dec"] for lbl in labels]
    aes_enc = [results[lbl]["AES Enc"] for lbl in labels]
    aes_dec = [results[lbl]["AES Dec"] for lbl in labels]

    x = range(len(labels))
    width = 0.2

    fig, ax = plt.subplots(figsize=(10, 6))

    ax.bar([i - 1.5*width for i in x], stream_enc, width, label='Stream Encrypt', color='#1f77b4')
    ax.bar([i - 0.5*width for i in x], stream_dec, width, label='Stream Decrypt', color='#aec7e8')
    ax.bar([i + 0.5*width for i in x], aes_enc, width, label='AES Encrypt', color='#d62728')
    ax.bar([i + 1.5*width for i in x], aes_dec, width, label='AES Decrypt', color='#ff9896')

    ax.set_ylabel('Execution Time (seconds)')
    ax.set_title('Performance Comparison: Stream Cipher vs AES-128 GCM')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    ax.grid(axis='y', linestyle='--', alpha=0.7)

    plt.tight_layout()
    chart_filename = "performance_graph.png"
    plt.savefig(chart_filename, dpi=300)
    print(f"\n[+] Graphical chart successfully saved as '{chart_filename}'")

if __name__ == "__main__":
    run_performance_tests()