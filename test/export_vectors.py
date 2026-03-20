import argparse
import csv
import io
import json
import sys
from pathlib import Path


if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")


def validate_vectors(vectors):
    required = {"key_len", "key", "plaintext", "ciphertext"}
    total = 0
    for mode, mode_vectors in vectors.items():
        if not isinstance(mode_vectors, list):
            print(f"ERROR: Mode '{mode}' is not a list")
            return False
        for i, vec in enumerate(mode_vectors):
            missing = required - set(vec)
            if missing:
                print(f"ERROR: Vector {mode}[{i}] missing fields: {missing}")
                return False
            for field in ("key", "iv", "plaintext", "ciphertext"):
                value = vec.get(field)
                if value is None:
                    if field == "iv":
                        continue
                    continue
                if not isinstance(value, str):
                    print(f"ERROR: Vector {mode}[{i}].{field} is not a string")
                    return False
                try:
                    int(value, 16)
                except ValueError:
                    print(f"ERROR: Vector {mode}[{i}].{field} is not valid hex")
                    return False
                if len(value) % 2:
                    print(f"ERROR: Vector {mode}[{i}].{field} has odd length (not byte-aligned)")
                    return False
            if vec["key_len"] // 8 != len(vec["key"]) // 2:
                print(f"WARNING: Vector {mode}[{i}] key_len={vec['key_len']} but key length is {(len(vec['key']) // 2) * 8} bits")
            total += 1
    print(f"Validated {total} vectors")
    return True


def export_json(vectors, output_path):
    print(f"\nExporting to {output_path}...")
    output_path.write_text(json.dumps(vectors, indent=2), encoding="utf-8")
    print(f"Exported {output_path.stat().st_size} bytes")
    print(output_path.name)


def export_csv(vectors, output_path):
    print(f"\nExporting to {output_path}...")
    with output_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Mode", "Key Length", "Key", "IV", "Plaintext", "Ciphertext"])
        for mode, mode_vectors in sorted(vectors.items()):
            for vec in mode_vectors:
                w.writerow([mode, vec["key_len"], vec["key"], vec.get("iv") or "", vec["plaintext"], vec["ciphertext"]])
    print(f"Exported {output_path.stat().st_size} bytes")
    print(output_path.name)


def export_c_header(vectors, output_path):
    print(f"\nExporting to {output_path}...")
    lines = [
        "#include <stdint.h>",
        "",
        "typedef struct {",
        "    const char *mode;",
        "    const char *key;",
        "    const char *iv;",
        "    const char *plaintext;",
        "    const char *ciphertext;",
        "    int key_len;",
        "} TestVector;",
        "",
    ]
    total = 0
    for mode, mode_vectors in sorted(vectors.items()):
        for i, vec in enumerate(mode_vectors, 1):
            name = f"{mode.lower()}_vector_{vec['key_len']}_{i}"
            iv = f'"{vec.get("iv")}"' if vec.get("iv") else "NULL"
            lines += [
                f"static const TestVector {name} = {{",
                f'    .mode = "{mode}",',
                f'    .key = "{vec["key"]}",',
                f"    .iv = {iv},",
                f'    .plaintext = "{vec["plaintext"]}",',
                f'    .ciphertext = "{vec["ciphertext"]}",',
                f"    .key_len = {vec['key_len']},",
                "};",
                "",
            ]
            total += 1
            
    # Add an array of pointers to all test vectors for easy iteration
    lines.append("static const TestVector* const nist_test_vectors[] = {")
    for mode, mode_vectors in sorted(vectors.items()):
        for i, vec in enumerate(mode_vectors, 1):
            name = f"{mode.lower()}_vector_{vec['key_len']}_{i}"
            lines.append(f"    &{name},")
    lines.append("};")
    lines.append(f"static const int num_nist_test_vectors = {total};")
    lines.append("")
    
    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Exported {output_path.stat().st_size} bytes ({total} vectors)")
    print(output_path.name)


def main():
    p = argparse.ArgumentParser(description="Export NIST AES Test Vectors")
    p.add_argument("--output", "-o", default="nist_vectors", help="Output file path stem")
    p.add_argument("--format", "-f", action="append", choices=["json", "csv", "c"], default=None)
    p.add_argument("--pdf", required=True, nargs="+", help="Paths to NIST PDF files")
    p.add_argument("--validate-only", action="store_true")
    a = p.parse_args()
    formats = a.format or ["json"]
    if len(formats) > 1 and formats[0] == "json":
        formats = formats[1:]
    print("\n" + "=" * 60)
    print("NIST AES Vector Export Utility")
    print("=" * 60)
    
    all_vectors = {}
    
    try:
        sys.path.insert(0, str(Path.cwd()))
        from parse_nist_pdf import NISTAESPDFParser

        for pdf_path in a.pdf:
            print(f"\nAttempting to parse PDF: {pdf_path}")
            vectors = NISTAESPDFParser(pdf_path).parse()
            if vectors:
                for mode, vecs in vectors.items():
                    all_vectors.setdefault(mode, []).extend(vecs)
                    
    except Exception as e:
        print(f"PDF parsing failed: {e}")
        return 1
        
    if not all_vectors:
        print("No vectors found in any PDF")
        return 1
        
    print(f"Successfully parsed PDFs\nFound {sum(len(v) for v in all_vectors.values())} total vectors")
    if not validate_vectors(all_vectors):
        return 1
    if a.validate_only:
        print("\nValidation complete")
        return 0
    stem = Path(a.output)
    parent = stem.parent if stem.parent != Path(".") else Path.cwd()
    name = stem.name
    print(f"\nExporting in formats: {', '.join(sorted(set(formats)))}")
    for fmt in set(formats):
        if fmt == "json":
            export_json(all_vectors, parent / f"{name}.json")
        elif fmt == "csv":
            export_csv(all_vectors, parent / f"{name}.csv")
        else:
            export_c_header(all_vectors, parent / f"{name}.h")
    print("\nExport complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())