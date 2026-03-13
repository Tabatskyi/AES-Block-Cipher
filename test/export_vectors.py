#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Export NIST AES Test Vectors to JSON

This utility parses the NIST AES_ModesA_All.pdf and exports vectors.

Usage:
    python export_vectors.py --pdf https://...pdf
    python export_vectors.py --pdf AES_ModesA_All.pdf --output vectors.json
    python export_vectors.py --pdf AES_ModesA_All.pdf --format csv --output vectors.csv
"""

import json
import sys
import io
import argparse
import csv
from pathlib import Path
from typing import Dict, List, Any

# Set UTF-8 encoding for output on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


def validate_vectors(vectors: Dict[str, List[Dict]]) -> bool:
    """Validate vector structure and content"""
    required_fields = {"key_len", "key", "plaintext", "ciphertext"}
    
    total = 0
    for mode, mode_vectors in vectors.items():
        if not isinstance(mode_vectors, list):
            print(f"ERROR: Mode '{mode}' is not a list")
            return False
        
        for i, vec in enumerate(mode_vectors):
            # Check required fields
            missing = required_fields - set(vec.keys())
            if missing:
                print(f"ERROR: Vector {mode}[{i}] missing fields: {missing}")
                return False
            
            # Validate hex strings
            for field in ["key", "iv", "plaintext", "ciphertext"]:
                if field not in vec or vec[field] is None:
                    if field == "iv":
                        continue  # IV is optional
                    continue
                
                value = vec[field]
                if not isinstance(value, str):
                    print(f"ERROR: Vector {mode}[{i}].{field} is not a string")
                    return False
                
                # Check hex format
                try:
                    int(value, 16)
                except ValueError:
                    print(f"ERROR: Vector {mode}[{i}].{field} is not valid hex")
                    return False
                
                # Check even length (byte boundaries)
                if len(value) % 2 != 0:
                    print(f"ERROR: Vector {mode}[{i}].{field} has odd length (not byte-aligned)")
                    return False
            
            # Validate key length
            expected_key_bytes = vec["key_len"] // 8
            actual_key_bytes = len(vec["key"]) // 2
            if expected_key_bytes != actual_key_bytes:
                print(f"WARNING: Vector {mode}[{i}] key_len={vec['key_len']} but key length is {actual_key_bytes*8} bits")
            
            total += 1
    
    print(f"✓ Validated {total} vectors")
    return True


def export_json(vectors: Dict[str, List[Dict]], output_path: Path):
    """Export vectors to JSON file"""
    print(f"\nExporting to {output_path}...")
    
    with open(output_path, 'w') as f:
        json.dump(vectors, f, indent=2)
    
    size = output_path.stat().st_size
    print(f"✓ Exported {size} bytes")
    print(f"✓ {output_path.name}")


def export_csv(vectors: Dict[str, List[Dict]], output_path: Path):
    """Export vectors to CSV for spreadsheet analysis"""
    print(f"\nExporting to {output_path}...")
    
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Mode", "Key Length", "Key", "IV", "Plaintext", "Ciphertext"])
        
        for mode, mode_vectors in sorted(vectors.items()):
            for vec in mode_vectors:
                writer.writerow([
                    mode,
                    vec["key_len"],
                    vec["key"],
                    vec.get("iv") or "",
                    vec["plaintext"],
                    vec["ciphertext"]
                ])
    
    size = output_path.stat().st_size
    print(f"✓ Exported {size} bytes")
    print(f"✓ {output_path.name}")


def export_c_header(vectors: Dict[str, List[Dict]], output_path: Path):
    """Export vectors as C source code"""
    print(f"\nExporting to {output_path}...")
    
    lines = []
    lines.append("/* Auto-generated NIST AES test vectors */")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append("typedef struct {")
    lines.append("    const char *key;")
    lines.append("    const char *iv;")
    lines.append("    const char *plaintext;")
    lines.append("    const char *ciphertext;")
    lines.append("    int key_len;")
    lines.append("} TestVector;")
    lines.append("")
    
    total = 0
    for mode, mode_vectors in sorted(vectors.items()):
        lines.append(f"/* {mode} Mode */")
        for i, vec in enumerate(mode_vectors):
            var_name = f"{mode.lower()}_vector_{vec['key_len']}_{i+1}"
            lines.append(f"static const TestVector {var_name} = {{")
            lines.append(f'    .key = "{vec["key"]}",')
            iv_str = f'"{vec["iv"]}"' if vec.get("iv") else "NULL"
            lines.append(f'    .iv = {iv_str},')
            lines.append(f'    .plaintext = "{vec["plaintext"]}",')
            lines.append(f'    .ciphertext = "{vec["ciphertext"]}",')
            lines.append(f'    .key_len = {vec["key_len"]},')
            lines.append("};")
            lines.append("")
            total += 1
    
    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))
    
    size = output_path.stat().st_size
    print(f"✓ Exported {size} bytes ({total} vectors)")
    print(f"✓ {output_path.name}")


def main():
    parser = argparse.ArgumentParser(
        description="Export NIST AES Test Vectors to Various Formats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --pdf AES_ModesA_All.pdf                      # Export to nist_vectors.json
  %(prog)s --pdf AES_ModesA_All.pdf --output vectors.json  # Custom output path
  %(prog)s --pdf AES_ModesA_All.pdf --format csv          # Export as CSV
  %(prog)s --pdf AES_ModesA_All.pdf --format c            # Export as C header
  %(prog)s --pdf https://csrc.nist.gov/.../AES_ModesA_All.pdf --format json  # Remote URL
        """
    )
    
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="nist_vectors",
        help="Output file path stem (default: nist_vectors)"
    )
    
    parser.add_argument(
        "--format", "-f",
        action="append",
        choices=["json", "csv", "c"],
        default=None,
        help="Export format (can specify multiple times, default: json)"
    )
    
    parser.add_argument(
        "--pdf",
        type=str,
        required=True,
        help="Path or URL to NIST AES_ModesA_All.pdf (REQUIRED)"
    )
    
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Only validate vectors, don't export"
    )
    
    args = parser.parse_args()
    
    # Set default format
    if args.format is None:
        args.format = ["json"]
    else:
        # Remove default 'json' if custom formats specified
        if len(args.format) > 1 and args.format[0] == "json":
            args.format = args.format[1:]
    
    # Load vectors from PDF
    vectors = {}
    
    print("\n" + "="*60)
    print("█ NIST AES Vector Export Utility")
    print("█"*60)
    
    print(f"\nAttempting to parse PDF: {args.pdf}")
    try:
        sys.path.insert(0, str(Path.cwd()))
        from parse_nist_pdf import NISTAESPDFParser
        
        parser_obj = NISTAESPDFParser(args.pdf)
        parsed = parser_obj.parse()
        
        if not parsed:
            print(f"[-] No vectors found in PDF")
            return 1
        
        print(f"✓ Successfully parsed PDF")
        print(f"  Found {sum(len(v) for v in parsed.values())} vectors")
        
        vectors = parsed
        
    except Exception as e:
        print(f"[-] PDF parsing failed: {e}")
        return 1
    
    # Validate
    print("\nValidating vectors...")
    if not validate_vectors(vectors):
        return 1
    
    if args.validate_only:
        print("\n✓ Validation complete")
        return 0
    
    # Export
    output_stem = args.output
    output_path = Path(output_stem)
    output_parent = output_path.parent if output_path.parent != Path('.') else Path.cwd()
    
    print(f"\nExporting in formats: {', '.join(set(args.format))}")
    
    for fmt in set(args.format):
        if fmt == "json":
            out_path = output_parent / f"{output_stem}.json"
            export_json(vectors, out_path)
        elif fmt == "csv":
            out_path = output_parent / f"{output_stem}.csv"
            export_csv(vectors, out_path)
        elif fmt == "c":
            out_path = output_parent / f"{output_stem}.h"
            export_c_header(vectors, out_path)
    
    print("\n✓ Export complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
