"""
run_tests.py - Test Runner for Digital Forensics Suite
Discovers and executes all unit and integration tests across crypto_lab, disk_forensics, and network_forensics.
"""

import sys
import unittest


def main():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_dirs = [
        "crypto_lab/tests",
        "disk_forensics/tests",
        "network_forensics/tests",
    ]

    for d in test_dirs:
        suite.addTests(loader.discover(d, pattern="test_*.py"))

    print("=" * 68)
    print("  DIGITAL FORENSICS SUITE — AUTOMATED VERIFICATION SUITE")
    print("=" * 68)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 68)
    print(f"Tests Run: {result.testsRun} | Failures: {len(result.failures)} | Errors: {len(result.errors)}")
    print("=" * 68)

    if not result.wasSuccessful():
        sys.exit(1)


if __name__ == "__main__":
    main()
