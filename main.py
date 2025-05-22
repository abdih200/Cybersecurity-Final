import socket
import hashlib
import os
import re
import requests
import subprocess
import platform
import getpass
import ftplib
import time


def main_menu():
    while True:
        print("\n=== Python Cybersecurity CLI Tool ===")
        print("1. Port Scanner")
        print("2. Password Strength Checker")
        print("3. SHA256 File Hash Verifier")
        print("4. Privilege Escalation Checker")
        print("5. System Info Reporter")
        print("6. FTP Brute Force Tool")
        print("7. Directory Fuzzer")
        print("8. Reverse Shell Simulator")
        print("9. Log File Analyzer")
        print("10. Login Attempt Logger")
        print("11. Firewall Rule Viewer")
        print("12. File Hash Monitor")
        print("13. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            port_scanner()
        elif choice == '2':
            password_strength_checker()
        elif choice == '3':
            file_hash_checker()
        elif choice == '4':
            privilege_checker()
        elif choice == '5':
            system_info_reporter()
        elif choice == '6':
            ftp_brute_force()
        elif choice == '7':
            directory_fuzzer()
        elif choice == '8':
            reverse_shell_simulator()
        elif choice == '9':
            log_file_analyzer()
        elif choice == '10':
            login_attempt_logger()
        elif choice == '11':
            firewall_rule_viewer()
        elif choice == '12':
            hash_monitor()
        elif choice == '13':
            print("Exiting...")
            break
        else:
            print("Invalid choice, try again.")


def port_scanner():
    target = input("Enter host to scan (e.g., 127.0.0.1): ")
    try:
        for port in range(20, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"[+] Port {port} is open")
            sock.close()
    except Exception as e:
        print(f"Error: {e}")


def password_strength_checker():
    password = input("Enter a password to test: ")
    strength = "Weak"
    if (len(password) >= 8 and re.search(r'[A-Z]', password) and
            re.search(r'[a-z]', password) and re.search(r'\d', password) and
            re.search(r'[@$!%*?&#]', password)):
        strength = "Strong"
    elif len(password) >= 6:
        strength = "Moderate"
    print(f"Password Strength: {strength}")


def file_hash_checker():
    file_path = input("Enter file path: ")
    try:
        with open(file_path, "rb") as f:
            bytes = f.read()
            readable_hash = hashlib.sha256(bytes).hexdigest()
            print(f"SHA256: {readable_hash}")
    except FileNotFoundError:
        print("File not found.")


def privilege_checker():
    if os.name == 'nt':  # Windows
        username = getpass.getuser()
        groups = subprocess.check_output("whoami /groups", shell=True).decode()
        if "S-1-5-32-544" in groups:  # SID for Administrators group
            print(f"[+] {username} has admin privileges.")
        else:
            print(f"[-] {username} does NOT have admin privileges.")
    else:
        if os.getuid() == 0:
            print("[+] Root privileges detected.")
        else:
            print("[-] Standard user privileges.")


def system_info_reporter():
    print("System Information:")
    print(f"OS: {platform.system()} {platform.release()}")
    print(f"Machine: {platform.machine()}")
    print(f"Processor: {platform.processor()}")
    print(f"Username: {getpass.getuser()}")


def ftp_brute_force():
    host = input("Enter FTP host (e.g., 127.0.0.1): ")
    username = input("Enter username to brute force: ")
    password_file = input("Enter path to password wordlist (e.g., passwords.txt): ")

    try:
        with open(password_file, 'r') as file:
            for line in file:
                password = line.strip()
                try:
                    ftp = ftplib.FTP(host)
                    ftp.login(user=username, passwd=password)
                    print(f"[+] Success! Username: {username}, Password: {password}")
                    ftp.quit()
                    return
                except ftplib.error_perm:
                    print(f"[-] Failed: {password}")
    except FileNotFoundError:
        print("Password file not found.")


def directory_fuzzer():
    base_url = input("Enter base URL (e.g., http://localhost/): ").rstrip("/")
    wordlist = input("Enter path to directory wordlist (e.g., common.txt): ")

    try:
        with open(wordlist, 'r') as file:
            for line in file:
                directory = line.strip()
                url = f"{base_url}/{directory}"
                try:
                    response = requests.get(url)
                    if response.status_code == 200:
                        print(f"[+] Found: {url}")
                except requests.RequestException:
                    continue
    except FileNotFoundError:
        print("Wordlist file not found.")


def reverse_shell_simulator():
    print("Simulating reverse shell (local test only)...")
    command = input("Enter a system command to execute (e.g., whoami): ")
    try:
        output = os.popen(command).read()
        print("Output:\n" + output)
    except Exception as e:
        print(f"Error: {e}")


def log_file_analyzer():
    log_path = input("Enter path to log file (e.g., system.log): ")
    try:
        with open(log_path, "r") as file:
            print("\nSuspicious Lines Found:")
            for line in file:
                if "error" in line.lower() or "fail" in line.lower() or "unauthorized" in line.lower():
                    print("[!] " + line.strip())
    except FileNotFoundError:
        print("Log file not found.")


def login_attempt_logger():
    log_file = "login_attempts.log"
    username = input("Enter username: ")
    password = input("Enter password: ")

    success = password == "admin123"  # Dummy password check
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    with open(log_file, "a") as log:
        log.write(f"{timestamp} | USER: {username} | SUCCESS: {success}\n")

    print("Login recorded.")
    if success:
        print("[+] Login successful.")
    else:
        print("[-] Invalid credentials.")


def firewall_rule_viewer():
    if os.name == 'nt':
        try:
            output = subprocess.check_output("netsh advfirewall firewall show rule name=all", shell=True).decode(
                errors="ignore")
            print("Firewall Rules (showing first 20 lines):\n")
            print("\n".join(output.splitlines()[:20]) + "\n... [truncated]")
        except Exception as e:
            print("Could not retrieve firewall rules:", e)
    else:
        print("This function is only supported on Windows.")


def hash_monitor():
    file_path = input("Enter path to monitor (e.g., C:\\Windows\\System32\\drivers\\etc\\hosts): ")
    try:
        with open(file_path, "rb") as file:
            content = file.read()
            file_hash = hashlib.sha256(content).hexdigest()
            print(f"[+] File SHA256: {file_hash}")
    except FileNotFoundError:
        print("File not found.")


if __name__ == "__main__":
    main_menu()
