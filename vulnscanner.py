#!/usr/bin/env python3

import os
import re
import random
import string
import subprocess
from termcolor import colored

# Generate a random filename for findings
def generate_random_filename():
    random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"findings_{random_str}.txt"

# Output file for findings
output_file = generate_random_filename()

# Regex patterns for vulnerabilities
PATTERNS = {
    "SQL_Injection": r"(?:SELECT|INSERT|UPDATE|DELETE).*?\bWHERE\b.*?\=.+",
    "XSS_Vulnerabilities": r"(?:<script>|alert\(|document\.cookie)",
    "CSRF_Tokens": r"csrf_token\s*=\s*[^\s;]+",
    "Hardcoded_Credentials": r"(?:username|password)\s*=\s*['\"][^\s'\"]+['\"]",
    "Sensitive_Endpoints": r"/api/v[0-9]+/[^\s]+",
    "Insecure_HTTP_Links": r"http://[^\s]+",
    "Debugging_Code": r"(?:console\.log|alert)\s*\(",
    "Eval_Function": r"eval\s*\(",
    "DOM_XSS": r"document\.write\s*\(",
    "Unencrypted_Data": r"(?:password|secret|api_key)\s*=\s*[^\s]+",
}

# Function to scan a file for vulnerabilities
def scan_file(file_path):
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()
            for category, pattern in PATTERNS.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    for match in matches:
                        findings.append(f"{category}: {match}")
    except Exception as e:
        print(colored(f"Error reading file {file_path}: {e}", "red"))
    return findings

# Function to save findings to a file
def save_findings(findings):
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("Vulnerability Findings:\n")
        f.write("\n".join(findings))
    print(colored(f"Findings saved to {output_file}", "green"))

# Function to run Kali Linux tools (optional)
def run_kali_tools(file_path):
    print(colored("Running Kali Linux tools for additional analysis...", "blue"))
    try:
        # Example: Run Nikto for web vulnerabilities
        subprocess.run(["nikto", "-h", file_path], check=True)
    except Exception as e:
        print(colored(f"Error running Kali Linux tools: {e}", "red"))

# Main function
def main():
    print(colored("""
  _    _           _   _      _____ _   _ _______ ______ _____  
 | |  | |   /\    | \ | |    |_   _| \ | |__   __|  ____|  __ \ 
 | |__| |  /  \   |  \| |______| | |  \| |  | |  | |__  | |__) |
 |  __  | / /\ \  | . ` |______| | | . ` |  | |  |  __| |  ___/ 
 | |  | |/ ____ \ | |\  |     _| |_| |\  |  | |  | |____| |     
 |_|  |_/_/    \_\|_| \_|    |_____|_| \_|  |_|  |______|_|     
    """, "cyan"))
    print(colored("Written by David Cantrell AKA Stryk3r", "yellow"))
    print(colored("D33pS33k", "magenta"))

    input_file = input("Enter the path to the HTML/JavaScript file to scan: ").strip()

    if not os.path.isfile(input_file):
        print(colored("Invalid file path. Please provide a valid file.", "red"))
        return

    print(colored(f"Scanning file: {input_file}", "blue"))
    findings = scan_file(input_file)

    if findings:
        print(colored("Vulnerabilities found:", "green"))
        for finding in findings:
            print(colored(finding, "green"))
    else:
        print(colored("No vulnerabilities found.", "green"))

    save_findings(findings)

    # Optional: Run Kali Linux tools for additional analysis
    if input("Do you want to run Kali Linux tools for additional analysis? (y/n): ").strip().lower() == "y":
        run_kali_tools(input_file)

if __name__ == "__main__":
    main()
