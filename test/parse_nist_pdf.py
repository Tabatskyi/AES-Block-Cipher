#!/usr/bin/env python3
"""
NIST AES PDF Test Vector Parser

This script parses the NIST AES_ModesA_All.pdf document to extract test vectors.
It supports both online URLs and local file paths.

Usage:
    python parse_nist_pdf.py
    python parse_nist_pdf.py https://csrc.nist.gov/CSRC/media/.../AES_ModesA_All.pdf
    python parse_nist_pdf.py /path/to/AES_ModesA_All.pdf
"""

import re
import sys
import io
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from urllib.request import urlopen
import json

# Try to import PDF libraries
try:
    import pdfplumber
    HAS_PDFPLUMBER = True
except ImportError:
    HAS_PDFPLUMBER = False
    print("Note: pdfplumber not installed. Install with: pip install pdfplumber")

try:
    import PyPDF2
    HAS_PYPDF2 = True
except ImportError:
    HAS_PYPDF2 = False

try:
    import fitz  # PyMuPDF
    HAS_FITZ = True
except ImportError:
    HAS_FITZ = False


class NISTAESPDFParser:
    """Parser for NIST AES Modes PDF documents"""
    
    def __init__(self, pdf_source: str):
        """
        Initialize parser with PDF source (URL or file path)
        
        Args:
            pdf_source: URL or local file path to PDF
        """
        self.pdf_source = pdf_source
        self.pdf_bytes = self._load_pdf()
    
    def _load_pdf(self) -> bytes:
        """Load PDF from URL or file"""
        if self.pdf_source.startswith(('http://', 'https://')):
            print(f"Downloading PDF from {self.pdf_source}...")
            with urlopen(self.pdf_source) as response:
                return response.read()
        else:
            print(f"Loading PDF from {self.pdf_source}...")
            with open(self.pdf_source, 'rb') as f:
                return f.read()
    
    def parse_with_pdfplumber(self) -> Dict[str, List[Dict]]:
        """Parse PDF using pdfplumber"""
        if not HAS_PDFPLUMBER:
            raise ImportError("pdfplumber not available. Install: pip install pdfplumber")
        
        vectors_by_mode = {}
        
        with pdfplumber.open(io.BytesIO(self.pdf_bytes)) as pdf:
            print(f"PDF has {len(pdf.pages)} pages")
            
            # Extract text from all pages
            full_text = ""
            for page_num, page in enumerate(pdf.pages):
                text = page.extract_text()
                full_text += f"\n--- Page {page_num + 1} ---\n"
                full_text += text
            
            # Parse sections
            vectors_by_mode = self._parse_vector_text(full_text)
        
        return vectors_by_mode
    
    def _parse_vector_text(self, text: str) -> Dict[str, List[Dict]]:
        """Extract test vectors from PDF text"""
        vectors = {}
        
        # Pattern to match test vector sections
        # Looking for patterns like "Key=" or "KEY="
        key_pattern = re.compile(r'Key\s*[:=]\s*([a-fA-F0-9\s]+)', re.IGNORECASE)
        iv_pattern = re.compile(r'IV\s*[:=]\s*([a-fA-F0-9\s]+)', re.IGNORECASE)
        pt_pattern = re.compile(r'Plaintext\s*[:=]\s*([a-fA-F0-9\s]+)', re.IGNORECASE)
        ct_pattern = re.compile(r'Ciphertext\s*[:=]\s*([a-fA-F0-9\s]+)', re.IGNORECASE)
        mode_pattern = re.compile(r'(ECB|CBC|CFB|OFB|CTR)', re.IGNORECASE)
        ke_pattern = re.compile(r'Encrypting?\s+(\d+)\s+(?:octet|byte)s', re.IGNORECASE)
        
        # Split by appendix/section markers
        sections = re.split(r'(?:APPENDIX|SECTION|===)', text, flags=re.IGNORECASE)
        
        for section in sections:
            lines = section.split('\n')
            
            # Try to identify mode from section
            mode_match = mode_pattern.search(section[:200])
            if not mode_match:
                continue
            
            mode = mode_match.group(1).upper()
            
            # Look for test vectors in this section
            key_matches = key_pattern.findall(section)
            iv_matches = iv_pattern.findall(section)
            pt_matches = pt_pattern.findall(section)
            ct_matches = ct_pattern.findall(section)
            
            # Clean hex strings
            def clean_hex(s):
                return re.sub(r'\s+', '', s.lower()) if s else ''
            
            for i, key in enumerate(key_matches[:3]):  # Limit to 3 per mode
                key_hex = clean_hex(key)
                if not key_hex:
                    continue
                
                iv_hex = clean_hex(iv_matches[i]) if i < len(iv_matches) else ''
                pt_hex = clean_hex(pt_matches[i]) if i < len(pt_matches) else ''
                ct_hex = clean_hex(ct_matches[i]) if i < len(ct_matches) else ''
                
                if pt_hex and ct_hex:
                    if mode not in vectors:
                        vectors[mode] = []
                    
                    vectors[mode].append({
                        'key': key_hex,
                        'iv': iv_hex if iv_hex else None,
                        'plaintext': pt_hex,
                        'ciphertext': ct_hex,
                        'key_len': len(key_hex) * 4  # bits
                    })
        
        return vectors
    
    def parse_with_pypdf2(self) -> str:
        """Parse PDF using PyPDF2 to extract text"""
        if not HAS_PYPDF2:
            raise ImportError("PyPDF2 not available. Install: pip install PyPDF2")
        
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(self.pdf_bytes))
        print(f"PDF has {len(pdf_reader.pages)} pages")
        
        text = ""
        for page_num, page in enumerate(pdf_reader.pages):
            text += f"\n--- Page {page_num + 1} ---\n"
            text += page.extract_text()
        
        return self._parse_vector_text(text)
    
    def parse_with_fitz(self) -> Dict[str, List[Dict]]:
        """Parse PDF using PyMuPDF for better text extraction"""
        if not HAS_FITZ:
            raise ImportError("PyMuPDF not available. Install: pip install PyMuPDF")
        
        pdf_document = fitz.open(stream=self.pdf_bytes, filetype="pdf")
        print(f"PDF has {len(pdf_document)} pages")
        
        text = ""
        for page_num in range(len(pdf_document)):
            page = pdf_document[page_num]
            text += f"\n--- Page {page_num + 1} ---\n"
            text += page.get_text()
        
        return self._parse_vector_text(text)
    
    def parse(self) -> Dict[str, List[Dict]]:
        """Parse PDF using best available library"""
        if HAS_PDFPLUMBER:
            return self.parse_with_pdfplumber()
        elif HAS_FITZ:
            return self.parse_with_fitz()
        elif HAS_PYPDF2:
            return self.parse_with_pypdf2()
        else:
            raise ImportError(
                "No PDF parsing library available.\n"
                "Install one of: pdfplumber, PyMuPDF, PyPDF2\n"
                "  pip install pdfplumber\n"
                "  pip install PyMuPDF\n"
                "  pip install PyPDF2"
            )


def main():
    if len(sys.argv) > 1:
        pdf_source = sys.argv[1]
    else:
        # Default to NIST URL
        pdf_source = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ModesA_All.pdf"
    
    try:
        parser = NISTAESPDFParser(pdf_source)
        vectors = parser.parse()
        
        print("\n" + "="*60)
        print("Extracted Test Vectors by Mode")
        print("="*60)
        
        total_vectors = 0
        for mode in sorted(vectors.keys()):
            mode_vectors = vectors[mode]
            print(f"\n{mode}:")
            for i, v in enumerate(mode_vectors, 1):
                print(f"  [{i}] {v['key_len']:3d}-bit key")
                print(f"      Key:  {v['key'][:32]}..." if len(v['key']) > 32 else f"      Key:  {v['key']}")
                if v['iv']:
                    print(f"      IV:   {v['iv']}")
                pt_disp = v['plaintext'][:40] + "..." if len(v['plaintext']) > 40 else v['plaintext']
                ct_disp = v['ciphertext'][:40] + "..." if len(v['ciphertext']) > 40 else v['ciphertext']
                print(f"      PT:   {pt_disp}")
                print(f"      CT:   {ct_disp}")
                total_vectors += 1
        
        print(f"\nTotal vectors extracted: {total_vectors}")
        
        # Export to JSON for use in testing
        output_file = Path(__file__).parent / "nist_vectors.json"
        with open(output_file, 'w') as f:
            # Convert for JSON serialization
            json_vectors = {}
            for mode, vecs in vectors.items():
                json_vectors[mode] = [
                    {
                        'key': v['key'],
                        'iv': v['iv'],
                        'plaintext': v['plaintext'],
                        'ciphertext': v['ciphertext'],
                        'key_len': v['key_len']
                    }
                    for v in vecs
                ]
            json.dump(json_vectors, f, indent=2)
        print(f"\nVectors exported to: {output_file}")
        
    except ImportError as e:
        print(f"Import Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
