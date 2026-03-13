import argparse
import io
import subprocess
import sys
from datetime import datetime
from pathlib import Path


if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")


class TestRunner:
    def __init__(self, workspace_root, pdf_path, verbose=False):
        if not pdf_path:
            raise ValueError("PDF path is required. Specify with --pdf-path")
        self.workspace = workspace_root
        self.bin_path = workspace_root / "build" / "AES_Block_Cipher.exe"
        self.pdf_path = pdf_path
        self.verbose = verbose
        self.vectors = {}

    def load_vectors(self):
        print("\n" + "=" * 70)
        print("VECTOR LOADING PHASE")
        print("=" * 70)
        print(f"\n[+] Parsing NIST PDF: {self.pdf_path}")
        try:
            sys.path.insert(0, str(self.workspace / "test"))
            from parse_nist_pdf import NISTAESPDFParser

            self.vectors = NISTAESPDFParser(self.pdf_path).parse() or {}
            if not self.vectors:
                print("[-] No vectors found in PDF")
                return False
            print("[+] Successfully parsed PDF")
            print(f"    Found {sum(len(v) for v in self.vectors.values())} vectors across modes")
            return True
        except Exception as e:
            print(f"[-] PDF parsing failed: {e}")
            return False

    def build_library(self):
        print("\n" + "=" * 70)
        print("BUILD PHASE")
        print("=" * 70)
        for cmd, ok_msg, fail_msg in [
            (["cmake", "-S", ".", "-B", "build"], "[+] CMake configured", "[-] CMake configure failed!"),
            (["cmake", "--build", "build"], "[+] Build successful", "[-] Build failed!"),
        ]:
            print(f"\n[+] Running: {' '.join(cmd)}")
            r = subprocess.run(cmd, cwd=str(self.workspace), capture_output=True, text=True)
            if r.returncode:
                print(fail_msg)
                if self.verbose:
                    print(r.stderr)
                return False
            print(ok_msg)
        return True

    def run_c_tests(self):
        print("\n" + "=" * 70)
        print("C LIBRARY TEST PHASE")
        print("=" * 70)
        if not self.bin_path.exists():
            print(f"[-] Binary not found: {self.bin_path}")
            return False
        print(f"\n[+] Executing: {self.bin_path}")
        try:
            r = subprocess.run([str(self.bin_path)], capture_output=True, text=True, timeout=30, cwd=str(self.workspace))
            out = r.stdout + r.stderr
            if self.verbose:
                print("\n--- Test Output ---")
                print(out)
                print("--- End Output ---\n")
            ok = r.returncode == 0
            print(f"[+] C Binary: {'PASS' if ok else 'FAIL'}")
            print(f"    Exit code: {r.returncode}")
            return ok
        except subprocess.TimeoutExpired:
            print("[-] Test execution timed out (>30s)")
            return False
        except Exception as e:
            print(f"[-] Error running tests: {e}")
            return False

    def generate_report(self, duration):
        lines = [
            "\n" + "=" * 70,
            "TEST REPORT",
            "=" * 70,
            f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Duration: {duration:.2f}s",
            f"Workspace: {self.workspace}",
            f"Binary: {self.bin_path}",
            "\n--- Test Coverage ---",
        ]
        lines += [f"{m:4s}: {len(v):2d} vectors" for m, v in sorted(self.vectors.items())]
        return "\n".join(lines)

    def run(self):
        start = datetime.now()
        print("\n" + "#" * 70)
        print("# NIST AES Test Suite with PDF Vector Parsing")
        print("#" * 70)
        if not self.load_vectors() or not self.build_library():
            return 1
        ok = self.run_c_tests()
        print(self.generate_report((datetime.now() - start).total_seconds()))
        print("\n[+] ALL TESTS PASSED" if ok else "\n[-] SOME TESTS FAILED")
        return 0 if ok else 1


def main():
    p = argparse.ArgumentParser(description="NIST AES Test Suite with PDF Vector Parsing")
    p.add_argument("--pdf-path", required=True, help="Path or URL to NIST AES_ModesA_All.pdf")
    p.add_argument("--verbose", "-v", action="store_true", help="Show detailed test output")
    a = p.parse_args()
    return TestRunner(Path(__file__).parent.parent, a.pdf_path, a.verbose).run()


if __name__ == "__main__":
    sys.exit(main())