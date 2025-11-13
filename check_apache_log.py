#!/usr/bin/env python3
# check_apache_log.py
# Author: Mehran Ebrahimi

import sys
import re

# This global list stores every log line from all files.
all_log_lines = []

# This regular expression helps to parse each log line.
# It gets: ip, datetime, request, status code, and size.
LOG_RE = re.compile(r'([\d\.]+) - - \[(.*?)\] "(.*?)" (\d+) ((\d+)|-).*')

# ---------------------------------------------------------
# Loading
# ---------------------------------------------------------
def load_logs(file_list):
    """
    Read all given files and store all lines in the global list.
    If a file cannot be opened, print a simple error and continue.
    """
    global all_log_lines
    all_log_lines = []  # reset in case the function runs again

    for fname in file_list:
        try:
            with open(fname, 'r', encoding='utf-8', errors='ignore') as f:
                # Read all lines and extend the global list
                lines = f.readlines()
                all_log_lines.extend(lines)
        except Exception as e:
            # Simple error message. Keep going to next file.
            print(f"[WARN] Could not open '{fname}': {e}")

    print(f"[INFO] Loaded {len(all_log_lines)} lines from {len(file_list)} file(s).")

# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------
def parse_line(line):
    """
    Try to match the line with the main regex.
    Return a dict with 'ip', 'code', 'request' if match; else None.
    """
    m = LOG_RE.match(line)
    if m is None:
        return None
    return {
        'ip': m.group(1),
        'code': m.group(4),
        'request': m.group(3)
    }

# ---------------------------------------------------------
# 2.2.4 How many total requests (Code 200)
# ---------------------------------------------------------
def count_code_200():
    """
    Count how many lines have status code 200.
    Print the total count at the end.
    """
    count = 0
    for line in all_log_lines:
        parsed = parse_line(line)
        if parsed and parsed['code'] == '200':
            count += 1
    print(count)

# ---------------------------------------------------------
# 2.2.5 How many requests from Seneca (IPs starting with 142.204)
# ---------------------------------------------------------
def count_from_seneca():
    """
    Count how many lines are from IPs that start with 142.204.
    Print the total count at the end.
    """
    count = 0
    for line in all_log_lines:
        parsed = parse_line(line)
        if parsed and parsed['ip'].startswith('142.204'):
            count += 1
    print(count)

# ---------------------------------------------------------
# 2.2.6 How many requests for OPS435_Lab
# ---------------------------------------------------------
def count_ops435_lab():
    """
    Count how many request strings contain 'OPS435_Lab'.
    Use a simple regex search on the request string.
    Print the total count at the end.
    """
    count = 0
    for line in all_log_lines:
        parsed = parse_line(line)
        if parsed and re.search(r'OPS435_Lab', parsed['request']):
            count += 1
    print(count)

# ---------------------------------------------------------
# 2.2.7 How many total "Not Found" requests (Code 404)
# ---------------------------------------------------------
def count_code_404():
    """
    Count how many lines have status code 404.
    Print the total count at the end.
    """
    count = 0
    for line in all_log_lines:
        parsed = parse_line(line)
        if parsed and parsed['code'] == '404':
            count += 1
    print(count)

# ---------------------------------------------------------
# 2.2.8 How many 404 requests contained "hidebots" in the URL
# ---------------------------------------------------------
def count_404_with_hidebots():
    """
    Count how many lines have code 404 AND have 'hidebots' in the request.
    Print the total count at the end.
    """
    count = 0
    for line in all_log_lines:
        parsed = parse_line(line)
        if parsed and parsed['code'] == '404':
            if re.search(r'hidebots', parsed['request']):
                count += 1
    print(count)

# ---------------------------------------------------------
# 2.2.9 Print all IP addresses that caused a 404 response
# ---------------------------------------------------------
def list_ips_with_404():
    """
    Collect all unique IPs that caused a 404 response.
    Use a dict to avoid duplicates.
    Print the list of keys at the end (one per line).
    """
    ip_dict = {}
    for line in all_log_lines:
        parsed = parse_line(line)
        if parsed and parsed['code'] == '404':
            ip_dict[parsed['ip']] = True

    # Print each IP on a new line, sorted for clean output
    for ip in sorted(ip_dict.keys()):
        print(ip)

# ---------------------------------------------------------
# Simple menu (from Part 1 idea, now with working actions)
# ---------------------------------------------------------
def print_menu():
    """
    Print the menu options. Keep it simple.
    """
    print("\n=== Apache Log Parser ===")
    print("1) How many total requests (Code 200)")
    print("2) How many requests from Seneca (IPs starting with 142.204)")
    print("3) How many requests for OPS435_Lab")
    print("4) How many total 'Not Found' requests (Code 404)")
    print("5) How many 404 requests contained 'hidebots' in the URL")
    print("6) Print all IP addresses that caused a 404 response")
    print("0) Exit")

def main():
    """
    Program entry point.
    Load logs first. Then show the menu and run the chosen action.
    """
    # Decide input files:
    # If filenames are given as args, use them.
    # If not, ask the user to type them.
    if len(sys.argv) > 1:
        files = sys.argv[1:]
    else:
        print("[INFO] Please enter one or more log file paths (space separated).")
        raw = input("> ").strip()
        files = raw.split() if raw else []

    if not files:
        print("[ERROR] No log files provided. Exiting.")
        sys.exit(1)

    # Load the logs at start (as the assignment asks).
    load_logs(files)

    # Menu loop
    while True:
        print_menu()
        choice = input("Select: ").strip()
        if choice == '1':
            count_code_200()
        elif choice == '2':
            count_from_seneca()
        elif choice == '3':
            count_ops435_lab()
        elif choice == '4':
            count_code_404()
        elif choice == '5':
            count_404_with_hidebots()
        elif choice == '6':
            list_ips_with_404()
        elif choice == '0':
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
