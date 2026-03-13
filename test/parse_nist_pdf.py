import importlib
import io
import json
import re
import sys
from pathlib import Path
from urllib.request import urlopen


def _opt_import(name, note=None):
    try:
        return importlib.import_module(name)
    except ImportError:
        if note:
            print(note)
        return None


pdfplumber = _opt_import("pdfplumber", "Note: pdfplumber not installed. Install with: pip install pdfplumber")
PyPDF2 = _opt_import("PyPDF2")
fitz = _opt_import("fitz")


class NISTAESPDFParser:
    def __init__(self, pdf_source):
        self.pdf_source = pdf_source
        self.pdf_bytes = self._load_pdf()

    def _load_pdf(self):
        if self.pdf_source.startswith(("http://", "https://")):
            print(f"Downloading PDF from {self.pdf_source}...")
            with urlopen(self.pdf_source) as r:
                return r.read()
        print(f"Loading PDF from {self.pdf_source}...")
        return Path(self.pdf_source).read_bytes()

    @staticmethod
    def _extract(pattern, text):
        m = pattern.search(text)
        if not m:
            return None
        s = re.sub(r"[^a-f0-9]", "", re.sub(r"\s+", "", m.group(1).lower()))
        return s or None

    def _parse_vector_text(self, text):
        vectors = {}
        pats = {
            "key": re.compile(r"Key\s+is\s+([A-Fa-f0-9\s\n]+?)(?=(?:IV|Plaintext|Ciphertext|Key)\s+(?:is|=)|\n\n|$)", re.MULTILINE),
            "iv": re.compile(r"IV\s+is\s+([A-Fa-f0-9\s\n]+?)(?=(?:Plaintext|Ciphertext|Key)\s+(?:is|=)|\n\n|$)", re.MULTILINE),
            "plaintext": re.compile(r"Plaintext\s+is\s+([A-Fa-f0-9\s\n]+?)(?=(?:Ciphertext|Key)\s+(?:is|=)|\n\n|$)", re.MULTILINE),
            "ciphertext": re.compile(r"Ciphertext\s+is\s+([A-Fa-f0-9\s\n]+?)(?=(?:Key)\s+(?:is|=)|ECB|CBC|CFB|OFB|CTR|\n\n|$)", re.MULTILINE),
        }
        mode_pat = re.compile(r"(ECB|CBC|CFB|OFB|CTR)(?:-AES)?[\s\(]*(\d+)?[^\n]*\n", re.IGNORECASE)
        for block in re.split(r"-{50,}", text):
            mm = mode_pat.search(block)
            if not mm:
                continue
            mode = mm.group(1).upper()
            vec = {k: self._extract(p, block) for k, p in pats.items()}
            if vec["key"] and vec["plaintext"] and vec["ciphertext"] and len(vec["plaintext"]) == len(vec["ciphertext"]):
                vec["key_len"] = len(vec["key"]) * 4
                vectors.setdefault(mode, []).append(vec)
        return vectors

    def parse_with_pdfplumber(self):
        if not pdfplumber:
            raise ImportError("pdfplumber not available. Install: pip install pdfplumber")
        with pdfplumber.open(io.BytesIO(self.pdf_bytes)) as pdf:
            print(f"PDF has {len(pdf.pages)} pages")
            text = "".join(f"\n--- Page {i + 1} ---\n{p.extract_text() or ''}" for i, p in enumerate(pdf.pages))
        return self._parse_vector_text(text)

    def parse_with_pypdf2(self):
        if not PyPDF2:
            raise ImportError("PyPDF2 not available. Install: pip install PyPDF2")
        reader = PyPDF2.PdfReader(io.BytesIO(self.pdf_bytes))
        print(f"PDF has {len(reader.pages)} pages")
        text = "".join(f"\n--- Page {i + 1} ---\n{p.extract_text() or ''}" for i, p in enumerate(reader.pages))
        return self._parse_vector_text(text)

    def parse_with_fitz(self):
        if not fitz:
            raise ImportError("PyMuPDF not available. Install: pip install PyMuPDF")
        doc = fitz.open(stream=self.pdf_bytes, filetype="pdf")
        print(f"PDF has {len(doc)} pages")
        text = "".join(f"\n--- Page {i + 1} ---\n{doc[i].get_text()}" for i in range(len(doc)))
        return self._parse_vector_text(text)

    def parse(self):
        if pdfplumber:
            return self.parse_with_pdfplumber()
        if fitz:
            return self.parse_with_fitz()
        if PyPDF2:
            return self.parse_with_pypdf2()
        raise ImportError(
            "No PDF parsing library available.\n"
            "Install one of: pdfplumber, PyMuPDF, PyPDF2\n"
            "  pip install pdfplumber\n"
            "  pip install PyMuPDF\n"
            "  pip install PyPDF2"
        )


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ModesA_All.pdf"
    try:
        vectors = NISTAESPDFParser(src).parse()
        print("\n" + "=" * 60)
        print("Extracted Test Vectors by Mode")
        print("=" * 60)
        total = 0
        for mode in sorted(vectors):
            print(f"\n{mode}:")
            for i, v in enumerate(vectors[mode], 1):
                print(f"  [{i}] {v['key_len']:3d}-bit key")
                print(f"      Key:  {v['key'][:32]}..." if len(v["key"]) > 32 else f"      Key:  {v['key']}")
                if v["iv"]:
                    print(f"      IV:   {v['iv']}")
                pt = v["plaintext"][:40] + "..." if len(v["plaintext"]) > 40 else v["plaintext"]
                ct = v["ciphertext"][:40] + "..." if len(v["ciphertext"]) > 40 else v["ciphertext"]
                print(f"      PT:   {pt}")
                print(f"      CT:   {ct}")
                total += 1
        print(f"\nTotal vectors extracted: {total}")
        out = Path(__file__).parent / "nist_vectors.json"
        with out.open("w", encoding="utf-8") as f:
            json.dump(vectors, f, indent=2)
        print(f"\nVectors exported to: {out}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()