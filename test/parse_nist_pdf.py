import importlib
import io
import re
import sys
import json
from pathlib import Path

def _opt_import(name, note=None):
    try:
        return importlib.import_module(name)
    except ImportError:
        return None

pdfplumber = _opt_import("pdfplumber")

class NISTAESPDFParser:
    def __init__(self, pdf_source):
        self.pdf_source = pdf_source
        self.pdf_bytes = Path(self.pdf_source).read_bytes()

    def _parse_text(self, text):
        vectors = {}
        mode_regex = re.compile(r"(ECB|CBC|CFB|OFB|CTR)-AES(\d+)\s*\(Encryption\)", re.IGNORECASE)
        sections = mode_regex.split(text)
        
        def clean_hex(s):
            return re.sub(r"[^A-Fa-f0-9]", "", s).lower()
            
        global_iv = None
        iv_match = re.search(r"IV is\s+([A-Fa-f0-9\s]+?)(?:Plaintext is|Key is|={5,})", text, re.IGNORECASE)
        if iv_match:
            global_iv = clean_hex(iv_match.group(1))

        if len(sections) < 4:
            return vectors
            
        for i in range(1, len(sections), 3):
            mode = sections[i].upper()
            if mode == 'CFB':
                mode = 'CFB128'
            key_len = int(sections[i+1])
            content = sections[i+2]
            
            content = re.split(r"\(Decryption\)", content)[0]
            
            # Skip non-128 segment lengths for CFB
            if "Segment Length =" in content and "Segment Length = 128" not in content:
                continue

            key_match = re.search(r"Key is\s+([A-Fa-f0-9\s]+?)(?:IV is|Plaintext is|Ciphertext is)", content, re.IGNORECASE)
            key_hex = clean_hex(key_match.group(1)) if key_match else ""
            
            iv_local_match = re.search(r"IV is\s+([A-Fa-f0-9\s]+?)(?:Plaintext is|Key is|Ciphertext is)", content, re.IGNORECASE)
            iv_hex = clean_hex(iv_local_match.group(1)) if iv_local_match else global_iv
            
            pt_match = re.search(r"Plaintext is\s+([A-Fa-f0-9\s]+?)(?:Ciphertext is|Block #1|Segment Length)", content, re.IGNORECASE)
            pt_hex = clean_hex(pt_match.group(1)) if pt_match else ""
            
            ct_match = re.search(r"Ciphertext is\s+([A-Fa-f0-9\s]+?)(?:={5,}|-|\Z)", content, re.IGNORECASE)
            ct_hex = clean_hex(ct_match.group(1)) if ct_match else ""
            
            if key_hex and pt_hex and ct_hex:
                vec = {
                    "mode": mode,
                    "key": key_hex,
                    "iv": iv_hex,
                    "plaintext": pt_hex,
                    "ciphertext": ct_hex,
                    "key_len": key_len
                }
                vectors.setdefault(mode, []).append(vec)
                
        return vectors

    def parse(self):
        with pdfplumber.open(io.BytesIO(self.pdf_bytes)) as pdf:
            text = "".join(f"\n{p.extract_text() or ''}" for p in pdf.pages)
        return self._parse_text(text)

def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "test/AES_ECB.pdf"
    vectors = NISTAESPDFParser(src).parse()
    print(json.dumps(vectors, indent=2))

if __name__ == '__main__':
    main()
