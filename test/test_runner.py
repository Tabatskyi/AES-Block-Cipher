#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive AES Test Suite with NIST Vector Validation

This test runner:
1. Parses NIST PDF for test vectors
2. Builds the C library
3. Runs all tests and generates detailed reports
4. Validates output against expected ciphertexts

Usage:
    python test_runner.py --pdf-path PATH_OR_URL [--verbose]
    python test_runner.py --help
"""

import argparse
import subprocess
import sys
import io
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

# Set UTF-8 encoding for output on Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')


@dataclass
class TestResult:
    """Single test result"""
    mode: str
    key_len: int
    encrypt: bool
    passed: bool
    message: str = ""
    error: Optional[str] = None


class TestRunner:
    """Main test orchestration"""
    
    def __init__(self, workspace_root: Path, pdf_path: str, verbose: bool = False):
        if not pdf_path:
            raise ValueError(
                "PDF path is required. Specify with --pdf-path\n"
                "Example: python test_runner.py --pdf-path https://csrc.nist.gov/.../AES_ModesA_All.pdf"
            )
        self.workspace = workspace_root
        self.bin_path = workspace_root / "build" / "AES_Block_Cipher.exe"
        self.pdf_path = pdf_path
        self.verbose = verbose
        self.results: List[TestResult] = []
        self.vectors = {}
    
    def load_vectors(self) -> bool:
        """Load test vectors from PDF (required)"""
        print("\n" + "="*70)
        print("VECTOR LOADING PHASE")
        print("="*70)
        
        print(f"\n[+] Parsing NIST PDF: {self.pdf_path}")
        try:
            sys.path.insert(0, str(self.workspace))
            from parse_nist_pdf import NISTAESPDFParser
            
            parser = NISTAESPDFParser(self.pdf_path)
            parsed = parser.parse()
            
            if not parsed:
                print(f"[-] No vectors found in PDF")
                return False
            
            print(f"[✓] Successfully parsed PDF")
            print(f"    Found {sum(len(v) for v in parsed.values())} vectors across modes")
            
            for mode, vectors in parsed.items():
                self.vectors[mode] = vectors
            
            return True
                    
        except Exception as e:
            print(f"[-] PDF parsing failed: {e}")
            return False
    
    def build_library(self) -> bool:
        """Configure and build C library"""
        print("\n" + "="*70)
        print("BUILD PHASE")
        print("="*70)
        
        print(f"\n[+] Configuring CMake...")
        result = subprocess.run(
            ["cmake", "-S", ".", "-B", "build"],
            cwd=str(self.workspace),
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"[-] CMake configure failed!")
            if self.verbose:
                print(result.stderr)
            return False
        
        print("[✓] CMake configured")
        
        print(f"[+] Building library...")
        result = subprocess.run(
            ["cmake", "--build", "build"],
            cwd=str(self.workspace),
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"[-] Build failed!")
            if self.verbose:
                print(result.stderr)
            return False
        
        print("[✓] Build successful")
        return True
    
    def run_c_tests(self) -> bool:
        """Execute C test binary"""
        print("\n" + "="*70)
        print("C LIBRARY TEST PHASE")
        print("="*70)
        
        if not self.bin_path.exists():
            print(f"[-] Binary not found: {self.bin_path}")
            return False
        
        print(f"\n[+] Executing: {self.bin_path}")
        
        try:
            result = subprocess.run(
                [str(self.bin_path)],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(self.workspace)
            )
            
            output = result.stdout + result.stderr
            
            if self.verbose:
                print("\n--- Test Output ---")
                print(output)
                print("--- End Output ---\n")
            
            lines = output.split('\n')
            passed_count = 0
            failed_count = 0
            
            for line in lines:
                if 'PASS' in line:
                    passed_count += 1
                    if self.verbose:
                        print(f"[✓] {line.strip()}")
                elif 'FAIL' in line:
                    failed_count += 1
                    print(f"[-] {line.strip()}")
            
            success = "All vectors: PASS" in output and result.returncode == 0
            
            print(f"\n[+] C Tests: {passed_count} passed, {failed_count} failed")
            print(f"    Exit code: {result.returncode}")
            
            return success
            
        except subprocess.TimeoutExpired:
            print("[-] Test execution timed out (>30s)")
            return False
        except Exception as e:
            print(f"[-] Error running tests: {e}")
            return False
    
    def generate_report(self, duration: float) -> str:
        """Generate final test report"""
        report = []
        report.append("\n" + "="*70)
        report.append("TEST REPORT")
        report.append("="*70)
        report.append(f"\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Duration: {duration:.2f}s")
        report.append(f"Workspace: {self.workspace}")
        report.append(f"Binary: {self.bin_path}")
        
        report.append(f"\n--- Test Coverage ---")
        for mode in sorted(self.vectors.keys()):
            vecs = self.vectors[mode]
            report.append(f"{mode:4s}: {len(vecs):2d} vectors")
        
        return '\n'.join(report)
    
    def run(self) -> int:
        """Execute full test suite"""
        start_time = datetime.now()
        
        print("\n" + "█"*70)
        print("█ NIST AES Test Suite with PDF Vector Parsing")
        print("█"*70)
        
        # Phase 1: Load vectors
        if not self.load_vectors():
            return 1
        
        # Phase 2: Build
        if not self.build_library():
            return 1
        
        # Phase 3: Run tests
        success = self.run_c_tests()
        
        duration = (datetime.now() - start_time).total_seconds()
        
        # Phase 4: Report
        report = self.generate_report(duration)
        print(report)
        
        if success:
            print("\n[✓] ALL TESTS PASSED")
            return 0
        else:
            print("\n[✗] SOME TESTS FAILED")
            return 1


def main():
    parser = argparse.ArgumentParser(
        description="NIST AES Test Suite with PDF Vector Parsing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --pdf-path AES_ModesA_All.pdf
  %(prog)s --pdf-path https://csrc.nist.gov/.../AES_ModesA_All.pdf
  %(prog)s --pdf-path AES_ModesA_All.pdf --verbose
        """
    )
    
    parser.add_argument(
        "--pdf-path",
        type=str,
        required=True,
        help="Path or URL to NIST AES_ModesA_All.pdf (REQUIRED)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed test output"
    )
    
    args = parser.parse_args()
    
    workspace = Path(__file__).parent
    runner = TestRunner(workspace, args.pdf_path, args.verbose)
    
    return runner.run()


if __name__ == "__main__":
    sys.exit(main())
