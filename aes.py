"""LIS4062 HW4: AES-256 file encryption, decryption, and avalanche tests.

Install: python -m pip install pycryptodome
Run from the project directory: python aes.py
Requires files/file1.txt and files/file2.pdf by default.

This is an academic experiment. EAX is used to encrypt/authenticate files;
ECB is used ONLY for isolated 128-bit-block avalanche testing.
"""

from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

ROOT = Path(__file__).resolve().parent
INPUT_DIR = ROOT / "files"
ENCRYPTED_DIR = ROOT / "encrypted"
DECRYPTED_DIR = ROOT / "decrypted"
FILES = ("file1.txt", "file2.pdf")
POSITIONS = {"Beginning": 0, "Middle": 15, "End": 31}


def flip_one_key_bit(key: bytes, position: int) -> bytes:
    modified = bytearray(key)
    modified[position] ^= 0x01
    return bytes(modified)


def bit_difference(first: bytes, second: bytes) -> int:
    if len(first) != len(second):
        raise ValueError("Ciphertexts must have equal length")
    return sum((a ^ b).bit_count() for a, b in zip(first, second))


def encrypt_file(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext


def decrypt_file(blob: bytes, key: bytes) -> bytes:
    if len(blob) < 32:
        raise ValueError("Invalid encrypted file")
    nonce, tag, ciphertext = blob[:16], blob[16:32], blob[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def file_avalanche(data: bytes, key: bytes) -> list[float]:
    # Keep the nonce fixed within each comparison; keys differ in one bit.
    # This tests AES-EAX ciphertext bits, excluding the nonce and tag.
    nonce = get_random_bytes(16)
    base = AES.new(key, AES.MODE_EAX, nonce=nonce).encrypt(data)
    total_bits = len(base) * 8
    results = []
    print("  Key position      Changed bits       Avalanche")
    for label, position in POSITIONS.items():
        changed_key = flip_one_key_bit(key, position)
        modified = AES.new(changed_key, AES.MODE_EAX, nonce=nonce).encrypt(data)
        changed = bit_difference(base, modified)
        percent = 100 * changed / total_bits
        results.append(percent)
        print(f"  {label:<16} {changed:>9} / {total_bits:<9} {percent:>9.2f}%")
    print(f"  Average: {sum(results)/len(results):.2f}%")
    return results


def block_avalanche(trials: int = 100) -> None:
    # ECB encrypts exactly one block here, not a file.
    print(f"\nAES-256 raw-block avalanche ({trials} independent trials per position)")
    print("  Key position       Changed bits (avg)    Avalanche (avg)")
    for label, position in POSITIONS.items():
        changed_total = 0
        for _ in range(trials):
            key = get_random_bytes(32)
            block = get_random_bytes(16)
            original = AES.new(key, AES.MODE_ECB).encrypt(block)
            modified = AES.new(flip_one_key_bit(key, position), AES.MODE_ECB).encrypt(block)
            changed_total += bit_difference(original, modified)
        print(f"  {label:<16} {changed_total/trials:>10.2f} / 128       {changed_total/(trials*128)*100:>8.2f}%")


def main() -> None:
    ENCRYPTED_DIR.mkdir(exist_ok=True)
    DECRYPTED_DIR.mkdir(exist_ok=True)
    print("=== LIS4062 HW4: AES-256 (EAX) ===")
    print("File                 Original      Encrypted     Decrypted     BER")

    datasets = []
    for filename in FILES:
        source = INPUT_DIR / filename
        if not source.is_file():
            print(f"Missing input: {source}")
            continue
        data = source.read_bytes()
        if not data:
            print(f"Empty input skipped for avalanche calculation: {source}")
            continue
        key = get_random_bytes(32)
        blob = encrypt_file(data, key)
        recovered = decrypt_file(blob, key)
        if recovered != data:
            raise AssertionError(f"Decryption mismatch: {filename}")

        (ENCRYPTED_DIR / f"{filename}.aes").write_bytes(blob)
        (DECRYPTED_DIR / filename).write_bytes(recovered)
        print(f"{filename:<20} {len(data):>8}      {len(blob):>8}      {len(recovered):>8}      0")
        datasets.append((filename, data, key))

    for filename, data, key in datasets:
        print(f"\nAES-EAX key avalanche: {filename} ({len(data)} bytes)")
        file_avalanche(data, key)

    block_avalanche(trials=100)
    print("\nDecryption verified byte-for-byte. BER = 0 for each tested file.")
    print("Note: AES-EAX tests and raw-block AES tests measure different things.")
    print("Values vary on each run because random keys/blocks are generated.")


if __name__ == "__main__":
    main()
