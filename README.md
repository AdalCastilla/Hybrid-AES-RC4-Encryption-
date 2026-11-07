# Hybrid AES-RC4 Encryption

LIS4062 Information Security, HW4, Autumn 2026 (UDLAP).
Replication of Atikah et al., "AES-RC4 Encryption Technique to Improve File Security" (ICIC 2019).

## Files

| File | Part | What it does |
|---|---|---|
| `aes.py` | 1 | AES-256 in EAX mode (PyCryptodome): file encryption, decryption, avalanche tests |
| `rc4.py` | 2 | RC4 from scratch: KSA, PRGA, encryption and decryption |
| `test_rc4.py` | 2 | RC4 known-answer test ("Key" / "Plaintext") |
| `schemes.py` | 3 | Chains `aes.py` and `rc4.py` into AES only, RC4 only, AES-RC4 and RC4-AES |
| `gen_files.py` | 3 | Generates the five test files (.docx, .xlsx, .pptx, .jpg, .pdf), seeded so everyone gets the same ones |
| `analysis.py` | 3 | Avalanche Effect, BER, file size, wrong-key and bit-flipping tests, timing |
| `results/` | 3 | Output of `analysis.py`: CSVs, `summary.json`, the figure and the LaTeX tables |

## Run

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt   # Windows: .venv\Scripts\pip
.venv/bin/python test_rc4.py
.venv/bin/python gen_files.py               # creates files/
.venv/bin/python analysis.py --selftest     # RC4 vector, AES-256 FIPS-197 vector, round trips
.venv/bin/python analysis.py                # all Part 3 experiments, about 30 s on 8 cores
```

`analysis.py` overwrites `results/`.
Everything except timing and the random-nonce BER tests is seeded, so the Avalanche Effect numbers come out identical on every run.

## Part 3 results

- With raw ciphertext bytes, every scheme has an Avalanche Effect between 49.75% and 50.17% (ideal 50%), so AES-RC4 does not beat the others.
- Base64-encoding the AES output, as PHP's `openssl_encrypt` does by default, reproduces the paper's 40.8% for AES only and RC4-AES and its 33% file-size increase.
- The paper's ~58% for AES-RC4 could not be reproduced with any output representation we tried.
- BER is 0 for all 20 scheme and file pairs.
- Schemes with AES-EAX reject a wrong key and a modified ciphertext; RC4 alone accepts both, so it is open to bit-flipping.
- `rc4.py` is pure Python and AES runs in compiled code, so the timing compares implementations, not algorithms.
