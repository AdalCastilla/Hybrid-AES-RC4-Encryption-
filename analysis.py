"""HW4 Part 3: Avalanche Effect, BER, file size, integrity and timing for
AES only, RC4 only, AES-RC4 (proposed) and RC4-AES.

Run:
    .venv/bin/python gen_files.py        # once, creates files/
    .venv/bin/python analysis.py --selftest
    .venv/bin/python analysis.py         # all experiments, ~1-2 min

Outputs: results/*.csv, results/summary.json, results/figures/p3_avalanche.png
and results/tables/*.tex (booktabs tables used in the LaTeX report).
"""

import argparse
import csv
import json
import os
import random
import statistics
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from Crypto.Cipher import AES

from schemes import (
    AES_RC4_ENCODINGS,
    BASE64_SCHEMES,
    HEADER_BYTES,
    SCHEMES,
    aes_decrypt_unverified,
    aes_key,
    bit_difference,
    rc4_key,
)
from rc4 import rc4_decrypt, rc4_encrypt

ROOT = Path(__file__).resolve().parent
FILES_DIR = ROOT / "files"
RESULTS = ROOT / "results"
FIGURES = RESULTS / "figures"
TABLES = RESULTS / "tables"

FILES = ["file1.docx", "file2.xlsx", "file3.pptx", "file4.jpg", "file5.pdf"]
SCHEME_NAMES = [s.name for s in SCHEMES]

# Table III of Atikah et al. (2019).
PAPER_KEYS = {
    "Original": ("universitas", "jayaabadi"),
    "Modified Key 1": ("vniversitas", "kayaabadi"),
    "Modified Key 2": ("univessitas", "jayabbadi"),
    "Modified Key 3": ("universitat", "jayaabadj"),
}
MODIFIED = ["Modified Key 1", "Modified Key 2", "Modified Key 3"]
POSITION_OF = {"Modified Key 1": "Beginning", "Modified Key 2": "Middle", "Modified Key 3": "End"}

# Average rows of Tables IV, V and VI in the paper ("Proposed" = AES-RC4).
PAPER_AE_AVG = {
    "Modified Key 1": {"AES only": 40.82, "RC4 only": 49.99, "RC4-AES": 40.78, "AES-RC4": 58.06},
    "Modified Key 2": {"AES only": 40.82, "RC4 only": 49.99, "RC4-AES": 40.80, "AES-RC4": 58.20},
    "Modified Key 3": {"AES only": 40.82, "RC4 only": 49.99, "RC4-AES": 40.76, "AES-RC4": 54.85},
}
PAPER_SIZES = {  # Table I and II of the paper: (original, after encryption)
    "file1.docx": (".doc", 430_592, 574_136),
    "file2.xlsx": (".xlsx", 13_140, 17_530),
    "file3.pptx": (".pptx", 122_469, 163_304),
    "file4.jpg": (".jpg", 64_170, 85_580),
    "file5.pdf": (".pdf", 348_524, 464_712),
}

# Fixed nonce shared by both encryptions of an AE pair (as in aes.py).
FIXED_NONCE = b"LIS4062-HW4-p3!!"
assert len(FIXED_NONCE) == 16

# Strict 1-bit experiment: same AES positions as the team's AES section
# (key byte 0, 15, 31, XOR 0x01); RC4 uses a 16-byte key, bytes 0, 7, 15.
STRICT_TRIALS = 20
RC4_STRICT_KEY_BYTES = 16
STRICT_POSITIONS = {"Beginning": (0, 0), "Middle": (15, 7), "End": (31, 15)}
TIMING_RUNS = 5


def read(name: str) -> bytes:
    return (FILES_DIR / name).read_bytes()


def ae_percent(a: bytes, b: bytes) -> float:
    """Formula (1) of the paper. Outputs of unequal length (only the UTF-8
    representation) are compared over their common length."""
    n = min(len(a), len(b))
    return 100.0 * bit_difference(a[:n], b[:n]) / (n * 8)


def flip(key: bytes, byte_index: int) -> bytes:
    k = bytearray(key)
    k[byte_index] ^= 0x01
    return bytes(k)


# ---------------------------------------------------------------- self test

def selftest() -> None:
    # RC4: the team's known-answer vector.
    assert rc4_encrypt(b"Plaintext", b"Key").hex().upper() == "BBF316E8D940AF0AD3"
    # AES-256: FIPS-197 Appendix C.3.
    kat = AES.new(bytes(range(32)), AES.MODE_ECB).encrypt(bytes.fromhex("00112233445566778899aabbccddeeff"))
    assert kat.hex() == "8ea2b7ca516745bfeafc49904b496089", kat.hex()
    # Every scheme round-trips every file with the paper keys (random nonce).
    ka, kr = aes_key("universitas"), rc4_key("jayaabadi")
    for name in FILES:
        data = read(name)
        for s in SCHEMES:
            assert s.decrypt(s.encrypt(data, ka, kr, None), ka, kr) == data, (s.name, name)
    print("selftest OK: RC4 vector, AES-256 FIPS-197 KAT, 4 schemes x 5 files round trip")


# ------------------------------------------------- AE with the paper's keys

def ae_paper_worker(name: str) -> list[dict]:
    data = read(name)
    rows = []
    variants = [
        ("raw", {s.name: s.encrypt for s in SCHEMES}),
        ("base64", BASE64_SCHEMES),
        ("aes_rc4_encoding", AES_RC4_ENCODINGS),
    ]
    for variant, encs in variants:
        for scheme, enc in encs.items():
            ka0, kr0 = (aes_key(PAPER_KEYS["Original"][0]), rc4_key(PAPER_KEYS["Original"][1]))
            base = enc(data, ka0, kr0, FIXED_NONCE)
            for mod in MODIFIED:
                ka, kr = aes_key(PAPER_KEYS[mod][0]), rc4_key(PAPER_KEYS[mod][1])
                other = enc(data, ka, kr, FIXED_NONCE)
                rows.append({
                    "variant": variant, "file": name, "key": mod, "scheme": scheme,
                    "changed_bits": round(ae_percent(base, other) * min(len(base), len(other)) * 8 / 100),
                    "total_bits": min(len(base), len(other)) * 8,
                    "ae_percent": ae_percent(base, other), "encrypted_bytes": len(base),
                })
    return rows


# --------------------------------------------- AE with a strict 1-bit flip

def strict_worker(task: tuple[int, str, int]) -> list[dict]:
    file_index, name, trial = task
    data = read(name)
    rng = random.Random(1000 * file_index + trial)
    ka = rng.randbytes(32)
    kr = rng.randbytes(RC4_STRICT_KEY_BYTES)
    nonce = rng.randbytes(16)
    rows = []
    for s in SCHEMES:
        base = s.encrypt(data, ka, kr, nonce)
        for pos, (ia, ir) in STRICT_POSITIONS.items():
            ka2 = flip(ka, ia) if s.uses_aes else ka
            kr2 = flip(kr, ir) if s.uses_rc4 else kr
            other = s.encrypt(data, ka2, kr2, nonce)
            rows.append({"file": name, "trial": trial, "position": pos, "scheme": s.name,
                         "ae_percent": ae_percent(base, other)})
    return rows


# --------------------------------- BER, sizes, wrong key, bit-flip attack

def decrypt_unverified(scheme: str, c: bytes, ka: bytes, kr: bytes) -> bytes:
    """What the receiver would get if the EAX tag were not checked."""
    if scheme == "AES only":
        return aes_decrypt_unverified(c, ka)
    if scheme == "RC4 only":
        return rc4_decrypt(c, kr)
    if scheme == "AES-RC4":
        return aes_decrypt_unverified(rc4_decrypt(c, kr), ka)
    if scheme == "RC4-AES":
        return rc4_decrypt(aes_decrypt_unverified(c, ka), kr)
    raise KeyError(scheme)


def try_decrypt(s, c: bytes, ka: bytes, kr: bytes):
    try:
        return s.decrypt(c, ka, kr), None
    except ValueError as exc:  # pycryptodome raises "MAC check failed"
        return None, str(exc)


def integrity_worker(task: tuple[int, str]) -> list[dict]:
    file_index, name = task
    data = read(name)
    total_bits = len(data) * 8
    rng = random.Random(500 + file_index)
    ka, kr = rng.randbytes(32), rng.randbytes(RC4_STRICT_KEY_BYTES)
    rows = []
    for s in SCHEMES:
        c = s.encrypt(data, ka, kr, None)  # normal use: random nonce
        dec, err = try_decrypt(s, c, ka, kr)
        assert err is None
        ber = bit_difference(data, dec) / total_bits

        # Wrong key: one bit flipped in every key the scheme uses.
        wka = flip(ka, 15) if s.uses_aes else ka
        wkr = flip(kr, 7) if s.uses_rc4 else kr
        wrong, wrong_err = try_decrypt(s, c, wka, wkr)
        wrong_unverified = decrypt_unverified(s.name, c, wka, wkr)

        # Bit-flipping attack: flip one bit in the middle of the ciphertext
        # body (after the nonce and tag when the outer layer is AES).
        start = HEADER_BYTES if s.uses_aes else 0
        pos = start + (len(c) - start) // 2
        tampered = bytearray(c)
        tampered[pos] ^= 0x01
        tampered = bytes(tampered)
        bfa, bfa_err = try_decrypt(s, tampered, ka, kr)
        bfa_unverified = decrypt_unverified(s.name, tampered, ka, kr)

        rows.append({
            "file": name, "scheme": s.name,
            "original_bytes": len(data), "encrypted_bytes": len(c), "decrypted_bytes": len(dec),
            "ber": ber,
            "wrong_key_rejected": wrong_err is not None,
            "wrong_key_ber": (bit_difference(data, wrong) / total_bits) if wrong is not None else None,
            "wrong_key_ber_unverified": bit_difference(data, wrong_unverified) / total_bits,
            "bfa_rejected": bfa_err is not None,
            "bfa_bits_changed": bit_difference(data, bfa) if bfa is not None else None,
            "bfa_bits_changed_unverified": bit_difference(data, bfa_unverified),
        })
    return rows


# ------------------------------------------------------------------ timing

def timing() -> list[dict]:
    rows = []
    ka, kr = aes_key("universitas"), rc4_key("jayaabadi")
    for name in FILES:
        data = read(name)
        for s in SCHEMES:
            enc_t, dec_t = [], []
            for _ in range(TIMING_RUNS):
                t0 = time.perf_counter()
                c = s.encrypt(data, ka, kr, None)
                t1 = time.perf_counter()
                s.decrypt(c, ka, kr)
                t2 = time.perf_counter()
                enc_t.append(t1 - t0)
                dec_t.append(t2 - t1)
            rows.append({"file": name, "scheme": s.name, "bytes": len(data),
                         "encrypt_ms": 1000 * statistics.median(enc_t),
                         "decrypt_ms": 1000 * statistics.median(dec_t)})
    return rows


# ----------------------------------------------------------------- outputs

def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def mean(xs) -> float:
    xs = list(xs)
    return sum(xs) / len(xs)


def summarize(ae_rows, strict_rows, integ_rows, time_rows) -> dict:
    s: dict = {"files": {}, "ae_paper": {}, "ae_base64": {}, "ae_strict": {}, "integrity": {}, "timing": {}}
    for name in FILES:
        r = next(x for x in integ_rows if x["file"] == name)
        s["files"][name] = {"bytes": r["original_bytes"]}
    for variant, key in (("raw", "ae_paper"), ("base64", "ae_base64")):
        for mod in MODIFIED:
            for scheme in SCHEME_NAMES:
                sel = [x for x in ae_rows if x["variant"] == variant and x["key"] == mod and x["scheme"] == scheme]
                s[key].setdefault(mod, {})[scheme] = {
                    "per_file": {x["file"]: x["ae_percent"] for x in sel},
                    "average": mean(x["ae_percent"] for x in sel),
                }
        for scheme in SCHEME_NAMES:
            sel = [x for x in ae_rows if x["variant"] == variant and x["scheme"] == scheme]
            s[key].setdefault("overall", {})[scheme] = mean(x["ae_percent"] for x in sel)
    s["ae_encodings"] = {
        enc: mean(x["ae_percent"] for x in ae_rows if x["variant"] == "aes_rc4_encoding" and x["scheme"] == enc)
        for enc in AES_RC4_ENCODINGS
    }
    for name in FILES:
        sel = [x for x in ae_rows if x["variant"] == "base64" and x["file"] == name and x["scheme"] == "AES only"]
        s["files"][name]["base64_encrypted_bytes"] = sel[0]["encrypted_bytes"]
    for pos in STRICT_POSITIONS:
        for scheme in SCHEME_NAMES:
            vals = [x["ae_percent"] for x in strict_rows if x["position"] == pos and x["scheme"] == scheme]
            s["ae_strict"].setdefault(pos, {})[scheme] = {
                "mean": mean(vals), "std": statistics.stdev(vals), "min": min(vals), "max": max(vals), "n": len(vals)}
    for scheme in SCHEME_NAMES:
        vals = [x["ae_percent"] for x in strict_rows if x["scheme"] == scheme]
        s["ae_strict"].setdefault("overall", {})[scheme] = {"mean": mean(vals), "std": statistics.stdev(vals),
                                                           "min": min(vals), "max": max(vals), "n": len(vals)}
    for r in integ_rows:
        s["integrity"].setdefault(r["scheme"], {})[r["file"]] = r
    for r in time_rows:
        s["timing"].setdefault(r["scheme"], {})[r["file"]] = r
    return s


def make_figure(summary: dict) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    # Colours: first three categorical slots of the dataviz reference palette
    # (validated: lightness, chroma, CVD separation). Exact values are in the tables.
    series = [
        ("Reported by Atikah et al. (2019)", "#2a78d6",
         [mean(PAPER_AE_AVG[m][sch] for m in MODIFIED) for sch in SCHEME_NAMES]),
        ("This work, raw bytes", "#eb6834", [summary["ae_paper"]["overall"][sch] for sch in SCHEME_NAMES]),
        ("This work, Base64 AES output", "#1baf7a", [summary["ae_base64"]["overall"][sch] for sch in SCHEME_NAMES]),
    ]
    ink, muted, grid = "#2b2b2b", "#6b6b6b", "#e4e4e0"
    plt.rcParams.update({"font.family": "serif", "font.size": 10})
    fig, ax = plt.subplots(figsize=(6.4, 3.4), dpi=300)
    width, gap = 0.26, 0.02
    xs = range(len(SCHEME_NAMES))
    for i, (label, color, vals) in enumerate(series):
        offs = [x + (i - 1) * (width + gap) for x in xs]
        ax.bar(offs, vals, width=width, color=color, label=label, zorder=3)
    ax.axhline(50, color=ink, linewidth=1, linestyle=(0, (4, 3)), zorder=4)
    ax.text(len(SCHEME_NAMES) - 0.5, 50.6, "ideal 50%", ha="right", va="bottom", color=ink, fontsize=8)
    ax.set_xticks(list(xs), SCHEME_NAMES, color=ink)
    ax.set_ylabel("Avalanche Effect (%)", color=ink)
    ax.set_ylim(30, 62)
    ax.yaxis.grid(True, color=grid, linewidth=0.8, zorder=0)
    ax.tick_params(colors=muted, length=0)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(muted)
    ax.legend(frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=3)
    fig.tight_layout()
    fig.savefig(FIGURES / "p3_avalanche.png", bbox_inches="tight")
    plt.close(fig)


# ------------------------------------------------------------ LaTeX tables

FILE_LABEL = {n: f"{n.split('.')[0].capitalize()} (.{n.split('.')[1]})" for n in FILES}


def pct(x: float) -> str:
    return f"{x:.2f}\\%"


def num(n: int) -> str:
    return f"{n:,}"


def table(label: str, caption: str, spec: str, header: str, body: list[str], small: bool = True) -> str:
    lines = ["\\begin{table}[htbp]", "\\centering", f"\\caption{{{caption}}}", f"\\label{{{label}}}"]
    if small:
        lines.append("\\small")
    lines += [f"\\begin{{tabular}}{{{spec}}}", "\\toprule", header + " \\\\", "\\midrule"]
    lines += body
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    return "\n".join(lines) + "\n"


def key_bits(a: str, b: str) -> int:
    return bit_difference(a.encode(), b.encode())


def write_tables(s: dict) -> None:
    TABLES.mkdir(parents=True, exist_ok=True)
    t = {}
    hdr_schemes = " & ".join(f"\\textbf{{{x}}}" for x in SCHEME_NAMES)

    # Table I: dataset
    body = [f"{FILE_LABEL[n]} & {PAPER_SIZES[n][0]} & {num(PAPER_SIZES[n][1])} & {num(s['files'][n]['bytes'])} \\\\"
            for n in FILES]
    t["dataset"] = table("tab:p3_dataset", "Dataset used for the comparison, with the corresponding file of Atikah et al.\\ (2019).",
                         "llrr", "\\textbf{File} & \\textbf{Paper ext.} & \\textbf{Paper size (B)} & \\textbf{Our size (B)}", body)

    # Table III: keys
    o_a, o_r = PAPER_KEYS["Original"]
    body = []
    for k, (a, r) in PAPER_KEYS.items():
        bits = "--" if k == "Original" else f"{key_bits(o_a, a)} / {key_bits(o_r, r)}"
        body.append(f"{k} & \\texttt{{{a}}} & \\texttt{{{r}}} & {bits} \\\\")
    t["keys"] = table("tab:p3_keys", "Keys of the paper's avalanche test (Table III of the original study) and number of key bits each modification actually changes.",
                      "llll", "\\textbf{Key} & \\textbf{AES key} & \\textbf{RC4 key} & \\textbf{Bits changed (AES / RC4)}", body)

    # Tables IV-VI of the paper, combined into one table (one block per key).
    body = []
    for i, mod in enumerate(MODIFIED):
        if i:
            body.append("\\midrule")
        body.append(f"\\multicolumn{{5}}{{l}}{{\\textit{{{mod} ({POSITION_OF[mod].lower()} of the key)}}}} \\\\")
        for n in FILES:
            body.append(f"{FILE_LABEL[n]} & " + " & ".join(pct(s['ae_paper'][mod][x]['per_file'][n]) for x in SCHEME_NAMES) + " \\\\")
        body.append("\\textbf{Average} & " + " & ".join(pct(s['ae_paper'][mod][x]['average']) for x in SCHEME_NAMES) + " \\\\")
        body.append("Paper average & " + " & ".join(pct(PAPER_AE_AVG[mod][x]) for x in SCHEME_NAMES) + " \\\\")
    t["ae_paper"] = table(
        "tab:p3_ae_paper",
        "Avalanche Effect between the original key and each modified key of Table~\\ref{tab:p3_keys}, measured on the raw ciphertext bytes. The last row of each block gives the average reported by Atikah et al.\\ (2019) in their Tables IV, V and VI.",
        "lrrrr", "\\textbf{File} & " + hdr_schemes, body)

    # Strict 1-bit flip
    body = []
    for pos in STRICT_POSITIONS:
        body.append(f"{pos} & " + " & ".join(
            f"{s['ae_strict'][pos][x]['mean']:.2f} $\\pm$ {s['ae_strict'][pos][x]['std']:.2f}" for x in SCHEME_NAMES) + " \\\\")
    body.append("\\midrule")
    body.append("All & " + " & ".join(
        f"{s['ae_strict']['overall'][x]['mean']:.2f} $\\pm$ {s['ae_strict']['overall'][x]['std']:.2f}" for x in SCHEME_NAMES) + " \\\\")
    body.append("Range & " + " & ".join(
        f"{s['ae_strict']['overall'][x]['min']:.2f}--{s['ae_strict']['overall'][x]['max']:.2f}" for x in SCHEME_NAMES) + " \\\\")
    t["ae_strict"] = table(
        "tab:p3_ae_strict",
        f"Avalanche Effect (\\%, mean $\\pm$ standard deviation) for an exact one-bit key change, {STRICT_TRIALS} random key pairs per file, five files per position.",
        "lrrrr", "\\textbf{Key position} & " + hdr_schemes, body)

    # Base64 variant
    body = []
    for x in SCHEME_NAMES:
        paper = mean(PAPER_AE_AVG[m][x] for m in MODIFIED)
        body.append(f"{x} & {pct(s['ae_paper']['overall'][x])} & {pct(s['ae_base64']['overall'][x])} & {pct(paper)} \\\\")
    ratio = mean(s["files"][n]["base64_encrypted_bytes"] / s["files"][n]["bytes"] for n in FILES)
    paper_ratio = mean(PAPER_SIZES[n][2] / PAPER_SIZES[n][1] for n in FILES)
    body.append("\\midrule")
    body.append(f"\\multicolumn{{4}}{{l}}{{Size ratio of the Base64 AES output: {ratio:.4f} (paper: {paper_ratio:.4f})}} \\\\")
    t["base64"] = table(
        "tab:p3_base64",
        "Average Avalanche Effect over the five files and three key modifications when the AES output is kept as raw bytes and when it is Base64 encoded, as the PHP implementation of the original study does by default.",
        "lrrr", "\\textbf{Scheme} & \\textbf{Raw bytes} & \\textbf{Base64} & \\textbf{Paper}", body)

    # Sizes (Tables II and VIII)
    body = []
    for n in FILES:
        enc = [s["integrity"][x][n]["encrypted_bytes"] for x in SCHEME_NAMES]
        dec = s["integrity"]["AES-RC4"][n]["decrypted_bytes"]
        body.append(f"{FILE_LABEL[n]} & {num(s['files'][n]['bytes'])} & " + " & ".join(num(e) for e in enc) + f" & {num(dec)} \\\\")
    t["sizes"] = table(
        "tab:p3_sizes",
        "File size in bytes before encryption, after encryption with each scheme, and after decryption (identical for every scheme).",
        "lrrrrrr", "\\textbf{File} & \\textbf{Original} & " + hdr_schemes + " & \\textbf{Decrypted}", body)

    # BER (Table VII)
    body = []
    for n in FILES:
        body.append(f"{FILE_LABEL[n]} & " + " & ".join(f"{s['integrity'][x][n]['ber']:g}" for x in SCHEME_NAMES) + " \\\\")
    t["ber"] = table("tab:p3_ber", "Bit Error Ratio between each original file and its decryption with the correct keys.",
                     "lrrrr", "\\textbf{File} & " + hdr_schemes, body)

    # Wrong key and bit-flipping attack
    body = []
    for x in SCHEME_NAMES:
        rows = list(s["integrity"][x].values())
        wk = "rejected (tag)" if all(r["wrong_key_rejected"] for r in rows) else "accepted"
        wk_ber = mean(r["wrong_key_ber_unverified"] for r in rows)
        bfa = "rejected (tag)" if all(r["bfa_rejected"] for r in rows) else "accepted"
        bits = sorted({r["bfa_bits_changed_unverified"] for r in rows})
        bits_s = ", ".join(str(b) for b in bits)
        body.append(f"{x} & {wk} & {wk_ber:.4f} & {bfa} & {bits_s} \\\\")
    t["integrity"] = table(
        "tab:p3_integrity",
        "Decryption with a key that differs in one bit, and decryption after one ciphertext bit is flipped (bit-flipping attack). BER and changed bits are measured on the output the receiver would obtain if the authentication tag were ignored.",
        "lllll",
        "\\textbf{Scheme} & \\textbf{Wrong key} & \\textbf{BER if accepted} & \\textbf{1-bit tamper} & \\textbf{Bits changed}",
        body)

    # Timing
    body = []
    total_bytes = sum(s["files"][n]["bytes"] for n in FILES)
    for x in SCHEME_NAMES:
        e = sum(s["timing"][x][n]["encrypt_ms"] for n in FILES)
        d = sum(s["timing"][x][n]["decrypt_ms"] for n in FILES)
        body.append(f"{x} & {e:,.1f} & {d:,.1f} & {total_bytes / 1e6 / (e / 1000):.2f} \\\\")
    t["timing"] = table(
        "tab:p3_timing",
        f"Time to encrypt and decrypt all five files ({num(total_bytes)} bytes, median of {TIMING_RUNS} runs).",
        "lrrr", "\\textbf{Scheme} & \\textbf{Encrypt (ms)} & \\textbf{Decrypt (ms)} & \\textbf{Encrypt MB/s}", body)

    for k, v in t.items():
        (TABLES / f"{k}.tex").write_text(v)


# -------------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    selftest()
    if args.selftest:
        return
    RESULTS.mkdir(exist_ok=True)
    FIGURES.mkdir(parents=True, exist_ok=True)

    t0 = time.perf_counter()
    time_rows = timing()  # alone, so other processes do not disturb the clock
    print(f"timing done ({time.perf_counter() - t0:.0f}s)")

    workers = max(1, (os.cpu_count() or 2) - 1)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        ae_rows = [r for rows in pool.map(ae_paper_worker, FILES) for r in rows]
        integ_rows = [r for rows in pool.map(integrity_worker, list(enumerate(FILES))) for r in rows]
        tasks = [(i, n, t) for i, n in enumerate(FILES) for t in range(STRICT_TRIALS)]
        strict_rows = [r for rows in pool.map(strict_worker, tasks) for r in rows]
    print(f"experiments done ({time.perf_counter() - t0:.0f}s)")

    write_csv(RESULTS / "ae_paper_keys.csv", ae_rows)
    write_csv(RESULTS / "ae_strict_1bit.csv", strict_rows)
    write_csv(RESULTS / "ber_integrity_sizes.csv", integ_rows)
    write_csv(RESULTS / "timing.csv", time_rows)
    summary = summarize(ae_rows, strict_rows, integ_rows, time_rows)
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2))
    make_figure(summary)
    write_tables(summary)

    print("\nAverage AE, paper keys (raw / Base64 / paper):")
    for x in SCHEME_NAMES:
        paper = mean(PAPER_AE_AVG[m][x] for m in MODIFIED)
        print(f"  {x:<9} {summary['ae_paper']['overall'][x]:6.2f}%  {summary['ae_base64']['overall'][x]:6.2f}%  {paper:6.2f}%")
    print("AES-RC4 with other output representations:")
    for enc, v in summary["ae_encodings"].items():
        print(f"  {enc:<28} {v:6.2f}%")
    print("Strict 1-bit AE (mean +- std):")
    for x in SCHEME_NAMES:
        o = summary["ae_strict"]["overall"][x]
        print(f"  {x:<9} {o['mean']:6.2f} +- {o['std']:.2f}  [{o['min']:.2f}, {o['max']:.2f}]")


if __name__ == "__main__":
    main()
