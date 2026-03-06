#!/usr/bin/env python3
"""
LazyS3-Py: Multi-threaded AWS S3 Bucket Brute-Forcer
Final Version: Integrated File Output and Threading
"""

import requests
import argparse
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

class S3Scanner:
    def __init__(self, target, threads=10, output_path=".", filename=None):
        self.target = target
        self.threads = threads
        self.output_full_path = os.path.join(output_path, filename or f"{target}.txt")
        self.environments = ['dev', 'stage', 'prod', 'test', 'assets', 'backup', 'public', 'private', 'logs']
        self.formats = ["{target}-{env}", "{target}.{env}", "{target}{env}", "{env}-{target}"]

    def validate_workspace(self):
        """Checks if the output directory is writable before starting."""
        output_dir = os.path.dirname(self.output_full_path) or "."
        if not os.access(output_dir, os.W_OK):
            print(f"[!] Error: Cannot write to directory '{output_dir}'. Check permissions.")
            sys.exit(1)
        print(f"[*] Results will be saved to: {self.output_full_path}")

    def generate_names(self):
        names = {self.target}
        for env in self.environments:
            for fmt in self.formats:
                names.add(fmt.format(target=self.target, env=env))
        return sorted(list(names))

    def check_bucket(self, name):
        url = f"https://{name}.s3.amazonaws.com"
        try:
            response = requests.head(url, timeout=5, allow_redirects=True)
            if response.status_code == 200:
                return f"[200 OK] Public: {url}"
            elif response.status_code == 403:
                return f"[403 Forbidden] Private: {url}"
        except:
            pass
        return None

    def run(self):
        self.validate_workspace()
        names = self.generate_names()
        print(f"[*] Scanning {len(names)} permutations with {self.threads} threads...")

        with open(self.output_full_path, "w") as f:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(self.check_bucket, name) for name in names]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        print(f"[!] Found: {result}")
                        f.write(result + "\n")
                        f.flush() # Ensure it writes to disk immediately

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-threaded S3 bucket brute-forcer.")
    parser.add_argument("-c", "--company", required=True, help="Target company keyword")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads (default: 10)")
    parser.add_argument("-o", "--output", default=".", help="Output directory (default: current)")
    parser.add_argument("-f", "--file", help="Custom filename (default: <company>.txt)")

    args = parser.parse_args()
    
    scanner = S3Scanner(
        target=args.company.lower(), 
        threads=args.threads, 
        output_path=args.output, 
        filename=args.file
    )
    scanner.run()
