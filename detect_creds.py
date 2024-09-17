#!/usr/bin/env python3
import argparse
import re
import sys
import os
import subprocess

# Define regex patterns for detecting hardcoded credentials
credential_patterns = [
    r'(?i)(password|passwd|pwd|secret|token|key|api_key|auth_token)\s*=\s*[\'"].+[\'"]',
    r'(?i)(password|passwd|pwd|secret|token|key|api_key|auth_token)\s*:\s*[\'"].+[\'"]',
    r'(?i)(password|passwd|pwd|secret|token|key|api_key|auth_token)\s*=>\s*[\'"].+[\'"]',
    r'(?i)(password|passwd|pwd|secret|token|key|api_key|auth_token)\s*:=\s*[\'"].+[\'"]',
    r'(?i)"(password|passwd|pwd|secret|token|key|api_key|auth_token)"\s*:\s*".+"',
    r"(?i)'(password|passwd|pwd|secret|token|key|api_key|auth_token)'\s*:\s*'.+'",
    r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64 strings
    r'0x[a-fA-F0-9]+',             # Hex strings
    r'[a-fA-F0-9]{32,}',           # Hashes
    r'^[a-f0-9]{32}(:.+)?$',                       # MD5 Hash
    r'^[a-f0-9]{40}(:.+)?$',                       # SHA-1 Hash
    r'^[a-f0-9]{64}(:.+)?$',                       # SHA-256 Hash
    r'^[a-f0-9]{128}(:.+)?$',                      # SHA-512 Hash
    r'^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$',    # bcrypt Hash
    r'^\$P\$[A-Za-z0-9./]{31}$',                   # PHPass Hash (WordPress, Joomla)
    r'^\$6\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}$',  # SHA-512 Crypt
    r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$',  # Base64
    r'AKIA[0-9A-Z]{16}',                           # AWS Access Key ID
    r'-----BEGIN (?:RSA )?PRIVATE KEY-----',       # Private RSA Key
]
]

def detect_hardcoded_credentials(line):
    for pattern in credential_patterns:
        match = re.search(pattern, line)
        if match:
            return match.group()
    return None

def remove_comments(line):
    # Remove single-line comments starting with //, #, --
    line = re.sub(r'//.*', '', line)
    line = re.sub(r'#.*', '', line)
    line = re.sub(r'--.*', '', line)
    # Remove multi-line comments starting with /* and ending with */
    line = re.sub(r'/\*.*\*/', '', line)
    return line

def run_hashid(hash_string):
    try:
        result = subprocess.run(['hashid', hash_string], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            return f"Error running hashid: {result.stderr.strip()}"
    except FileNotFoundError:
        return "Error: hashid tool not found. Please ensure it is installed and in your PATH."

def process_file(file_path, exclude_comments=False, verbose=False, suppress_output=False, use_hashid=False):
    if not os.path.isfile(file_path):
        if not suppress_output:
            print(f"Error: File '{file_path}' not found.")
        return []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        if not suppress_output:
            print(f"Error reading file '{file_path}': {e}")
        return []
    results = []
    for idx, line in enumerate(lines, 1):
        original_line = line
        if exclude_comments:
            line = remove_comments(line)
        matched_credential = detect_hardcoded_credentials(line)
        if matched_credential:
            hashid_output = ""
            if use_hashid:
                hashid_output = run_hashid(matched_credential)
            results.append((idx, original_line.strip(), hashid_output))
            if verbose and not suppress_output:
                print(f"Possible credential found in '{file_path}' at line {idx}: {original_line.strip()}")
                if use_hashid and hashid_output:
                    print(f"HashID Output:\n{hashid_output}")
        elif verbose and not suppress_output:
            print(f"No credential found in line {idx}.")
    return results

def validate_line(file_path, line_number, use_hashid=False):
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    if line_number < 1 or line_number > len(lines):
        print(f"Error: Line number {line_number} is out of range.")
        sys.exit(1)
    line = lines[line_number - 1]
    matched_credential = detect_hardcoded_credentials(line)
    if matched_credential:
        print(f"Line {line_number} contains hardcoded credentials: {line.strip()}")
        if use_hashid:
            hashid_output = run_hashid(matched_credential)
            print(f"HashID Output:\n{hashid_output}")
    else:
        print(f"Line {line_number} does not contain hardcoded credentials.")

def run_wizard():
    print("Welcome to the Hardcoded Credentials Detector Wizard!")
    file = input("Enter the path to the code file or directory to scan: ")
    exclude_comments = input("Exclude comments? (y/n): ").lower() == 'y'
    recursive = False
    if os.path.isdir(file):
        recursive = input("Recursively scan directories? (y/n): ").lower() == 'y'
    verbose = input("Enable verbose output? (y/n): ").lower() == 'y'
    use_hashid = input("Use hashid to identify hash types? (y/n): ").lower() == 'y'
    output = input("Enter output file (leave blank for none): ")
    return {
        'file': file,
        'exclude_comments': exclude_comments,
        'verbose': verbose,
        'output': output,
        'recursive': recursive,
        'use_hashid': use_hashid,
    }

def scan_directory(directory, exclude_comments=False, verbose=False, file_types=None, use_hashid=False):
    results = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file_types:
                if not any(file.endswith(ext) for ext in file_types):
                    continue
            file_path = os.path.join(root, file)
            file_results = process_file(file_path, exclude_comments, verbose, suppress_output=True, use_hashid=use_hashid)
            if file_results:
                results.append((file_path, file_results))
    return results

def main():
    parser = argparse.ArgumentParser(description='Detect hardcoded credentials in code files.')
    parser.add_argument('file', nargs='?', help='The code file or directory to scan.')
    parser.add_argument('-l', '--line', type=int, help='Line number to validate.')
    parser.add_argument('-w', '--wizard', action='store_true', help='Run in wizard mode.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output.')
    parser.add_argument('-o', '--output', help='Output results to a file.')
    parser.add_argument('-e', '--exclude-comments', action='store_true', help='Exclude comments.')
    parser.add_argument('--file-types', nargs='+', help='Specify file types to scan.')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursively scan directories.')
    parser.add_argument('--use-hashid', action='store_true', help='Use hashid tool to identify hash types.')
    args = parser.parse_args()
    
    if args.wizard:
        options = run_wizard()
        args.file = options.get('file', args.file)
        args.exclude_comments = options.get('exclude_comments', args.exclude_comments)
        args.verbose = options.get('verbose', args.verbose)
        args.output = options.get('output', args.output)
        args.recursive = options.get('recursive', args.recursive)
        args.use_hashid = options.get('use_hashid', args.use_hashid)
    
    if not args.file:
        print("Error: No file or directory specified.")
        sys.exit(1)
    
    if args.recursive and os.path.isdir(args.file):
        if args.file_types:
            file_types = args.file_types
        else:
            file_types = None
        results = scan_directory(args.file, args.exclude_comments, args.verbose, file_types, args.use_hashid)
        if results:
            print("Possible hardcoded credentials found:")
            for file_path, file_results in results:
                print(f"\nIn file: {file_path}")
                for idx, line, hashid_output in file_results:
                    print(f"Line {idx}: {line}")
                    if args.use_hashid and hashid_output:
                        print(f"HashID Output:\n{hashid_output}")
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    for file_path, file_results in results:
                        f.write(f"\nIn file: {file_path}\n")
                        for idx, line, hashid_output in file_results:
                            f.write(f"Line {idx}: {line}\n")
                            if args.use_hashid and hashid_output:
                                f.write(f"HashID Output:\n{hashid_output}\n")
        else:
            print("No hardcoded credentials found.")
    else:
        if args.line:
            validate_line(args.file, args.line, args.use_hashid)
        else:
            results = process_file(args.file, args.exclude_comments, args.verbose, use_hashid=args.use_hashid)
            if results:
                print("Possible hardcoded credentials found:")
                for idx, line, hashid_output in results:
                    print(f"Line {idx}: {line}")
                    if args.use_hashid and hashid_output:
                        print(f"HashID Output:\n{hashid_output}")
                if args.output:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        for idx, line, hashid_output in results:
                            f.write(f"Line {idx}: {line}\n")
                            if args.use_hashid and hashid_output:
                                f.write(f"HashID Output:\n{hashid_output}\n")
            else:
                print("No hardcoded credentials found.")

if __name__ == '__main__':
    main()
