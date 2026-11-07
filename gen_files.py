"""Generate the five test files for HW4 Part 3.

The files are byte-for-byte deterministic (fixed seeds, fixed timestamps)
so every team member gets the same dataset. Sizes are tuned to be close to Table I of Atikah et al. (2019):
.doc(x) 430,592 B, .xlsx 13,140 B, .pptx 122,469 B, .jpg 64,170 B, .pdf 348,524 B.

Run: .venv/bin/python gen_files.py
"""

import datetime as dt
import io
import random
import re
import zipfile
from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "files"

TARGETS = {
    "file1.docx": 430_592,
    "file2.xlsx": 13_140,
    "file3.pptx": 122_469,
    "file4.jpg": 64_170,
    "file5.pdf": 348_524,
}

# Office files and PDFs embed the time they were written; pin it so that
# reruns produce identical bytes (and therefore identical measurements).
FIXED_TIME = dt.datetime(2026, 11, 1, tzinfo=dt.timezone.utc)
FIXED_ZIP_TIME = (2026, 11, 1, 0, 0, 0)
FIXED_ISO = "2026-11-01T00:00:00Z"

WORDS = (
    "data security encryption key cipher block stream network information "
    "file confidential integrity algorithm round permutation byte message "
    "university report analysis protection access attack signal channel"
).split()


def sentence(rng: random.Random, n: int = 14) -> str:
    words = [rng.choice(WORDS) for _ in range(n)]
    return " ".join(words).capitalize() + "."


def normalize_ooxml(path: Path) -> None:
    """Rewrite a .docx/.xlsx/.pptx with fixed timestamps inside and on every zip entry."""
    with zipfile.ZipFile(path) as src:
        entries = [(info, src.read(info.filename)) for info in src.infolist()]
    with zipfile.ZipFile(path, "w") as dst:
        for info, data in entries:
            if info.filename == "docProps/core.xml":
                text = data.decode("utf-8")
                text = re.sub(r"(<dcterms:(?:created|modified)[^>]*>)[^<]*(<)", rf"\g<1>{FIXED_ISO}\g<2>", text)
                data = text.encode("utf-8")
            fixed = zipfile.ZipInfo(info.filename, date_time=FIXED_ZIP_TIME)
            fixed.compress_type = info.compress_type
            fixed.external_attr = info.external_attr
            dst.writestr(fixed, data)


def photo_like(seed: int, width: int, height: int) -> Image.Image:
    """Smooth gradients plus noise, so JPEG behaves like a real photo."""
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:height, 0:width] / max(width, height)
    channels = []
    for _ in range(3):
        a, b, c = rng.uniform(2, 9, 3)
        base = 0.5 + 0.25 * np.sin(a * x + b * y) + 0.2 * np.cos(c * x * y * 4)
        channels.append(base + rng.normal(0, 0.06, base.shape))
    arr = np.clip(np.stack(channels, axis=-1) * 255, 0, 255).astype(np.uint8)
    return Image.fromarray(arr)


def jpeg_bytes(img: Image.Image, target: int) -> bytes:
    """Binary-search the JPEG quality so the output is close to target."""
    lo, hi, best = 5, 95, None
    while lo <= hi:
        q = (lo + hi) // 2
        buf = io.BytesIO()
        img.save(buf, "JPEG", quality=q)
        data = buf.getvalue()
        if best is None or abs(len(data) - target) < abs(len(best) - target):
            best = data
        if len(data) < target:
            lo = q + 1
        else:
            hi = q - 1
    return best


def make_jpg(path: Path, target: int) -> None:
    path.write_bytes(jpeg_bytes(photo_like(4, 640, 480), target))


def make_docx(path: Path, target: int) -> None:
    from docx import Document
    from docx.shared import Inches

    rng = random.Random(1)
    doc = Document()
    doc.add_heading("Information Security Report", 0)
    for section in range(1, 9):
        doc.add_heading(f"Section {section}", level=1)
        for _ in range(12):
            doc.add_paragraph(" ".join(sentence(rng) for _ in range(5)))
    # Images take most of the space, as in a typical report.
    image_budget = target - 60_000
    per_image = image_budget // 4
    for i in range(4):
        doc.add_heading(f"Figure {i + 1}", level=2)
        doc.add_picture(io.BytesIO(jpeg_bytes(photo_like(10 + i, 900, 650), per_image)), width=Inches(5.5))
    doc.save(path)


def make_xlsx(path: Path, target: int) -> None:
    from openpyxl import Workbook

    rng = random.Random(2)
    wb = Workbook()
    ws = wb.active
    ws.title = "Grades"
    ws.append(["ID", "Name", "Exam 1", "Exam 2", "Homework", "Average"])
    rows = 180
    for r in range(2, rows + 2):
        ws.append([
            170000 + r,
            f"Student {r - 1}",
            rng.randint(50, 100),
            rng.randint(50, 100),
            rng.randint(60, 100),
            f"=AVERAGE(C{r}:E{r})",
        ])
    wb.save(path)


def make_pptx(path: Path, target: int) -> None:
    from pptx import Presentation
    from pptx.util import Inches

    rng = random.Random(3)
    prs = Presentation()
    title = prs.slides.add_slide(prs.slide_layouts[0])
    title.shapes.title.text = "Hybrid AES-RC4 Encryption"
    title.placeholders[1].text = "LIS4062 Information Security"
    for i in range(6):
        slide = prs.slides.add_slide(prs.slide_layouts[1])
        slide.shapes.title.text = f"Topic {i + 1}"
        slide.placeholders[1].text = "\n".join(sentence(rng, 8) for _ in range(4))
    for i in range(2):
        slide = prs.slides.add_slide(prs.slide_layouts[5])
        slide.shapes.title.text = f"Diagram {i + 1}"
        img = jpeg_bytes(photo_like(20 + i, 800, 500), (target - 40_000) // 2)
        slide.shapes.add_picture(io.BytesIO(img), Inches(1), Inches(1.6), width=Inches(8))
    prs.save(path)


def make_pdf(path: Path, target: int) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages

    rng = np.random.default_rng(5)
    with PdfPages(path, metadata={"CreationDate": FIXED_TIME}) as pdf:
        for page in range(6):
            fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8.5, 11))
            ax1.set_title(f"Page {page + 1}: measured throughput")
            ax1.plot(np.cumsum(rng.normal(0, 1, 4000)))
            # Small raster: matplotlib embeds images losslessly, so keep it modest.
            ax2.imshow(np.asarray(photo_like(30 + page, 100, 70)))
            ax2.axis("off")
            pdf.savefig(fig)
            plt.close(fig)


MAKERS = {
    "file1.docx": make_docx,
    "file2.xlsx": make_xlsx,
    "file3.pptx": make_pptx,
    "file4.jpg": make_jpg,
    "file5.pdf": make_pdf,
}


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, maker in MAKERS.items():
        path = OUT / name
        maker(path, TARGETS[name])
        if path.suffix in (".docx", ".xlsx", ".pptx"):
            normalize_ooxml(path)
        size = path.stat().st_size
        print(f"{name:<12} {size:>9,} bytes  (paper: {TARGETS[name]:>9,})")


if __name__ == "__main__":
    main()
