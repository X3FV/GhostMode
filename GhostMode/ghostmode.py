#!/usr/bin/env python3
"""
GhostMode - Tor-Powered Command Execution Tool

Usage:
  ghostmode.py --tool "command"
  ghostmode.py --new-ip
  ghostmode.py --show-ip
  ghostmode.py --check
"""

import argparse
import os
import subprocess
import sys
import time
import socket
from datetime import datetime

class GhostMode:
    def __init__(self):
        self.tor_control_port = 9051
        self.tor_proxy = "socks5 127.0.0.1 9050"
        self.proxychains_conf = "/etc/proxychains.conf"
        self.tor_service = "tor"
        self.log_file = None
        self.stealth_mode = False
        self.current_ip = None

    def parse_arguments(self):
        parser = argparse.ArgumentParser(
            description="GhostMode: Execute commands through Tor with Proxychains",
            epilog="Use responsibly and only on authorized systems."
        )
        parser.add_argument(
            "--tool", 
            help="Command/tool to run through Tor (e.g., 'nmap -sS target.com')"
        )
        parser.add_argument(
            "--stealth", 
            action="store_true",
            help="Rotate Tor identity between each command execution"
        )
        parser.add_argument(
            "--log", 
            help="Log session to specified file"
        )
        parser.add_argument(
            "--check", 
            action="store_true",
            help="Verify Tor and Proxychains configuration only"
        )
        parser.add_argument(
            "--new-ip", 
            action="store_true",
            help="Request a new Tor exit IP"
        )
        parser.add_argument(
            "--show-ip", 
            action="store_true",
            help="Show current Tor exit IP"
        )
        return parser.parse_args()

    def run_command(self, command, background=False):
        try:
            if background:
                process = subprocess.Popen(
                    command, 
                    shell=True, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE
                )
                return process
            else:
                result = subprocess.run(
                    command, 
                    shell=True, 
                    check=True, 
                    text=True,
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE
                )
                return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"[!] Command failed: {e.stderr}")
            return None

    def check_tor(self):
        # Check if Tor is installed
        if not os.path.exists("/usr/sbin/tor") and not os.path.exists("/usr/bin/tor"):
            print("[-] Tor is not installed. Please install Tor first.")
            print("    On Debian/Ubuntu: sudo apt install tor")
            print("    On Fedora/RHEL: sudo dnf install tor")
            return False

        # Check if Tor is running (fixed the unclosed parenthesis here)
        try:
            socket.create_connection(("127.0.0.1", 9050), 2)
            print("[+] Tor is running")
            return True
        except (socket.error, ConnectionRefusedError):
            print("[!] Tor is not running. Attempting to start...")
            result = self.run_command("sudo service tor start")
            if result is None:
                print("[-] Failed to start Tor service")
                return False
            time.sleep(5)  # Give Tor time to start
            return self.check_tor()

    def check_proxychains_config(self):
        if not os.path.exists(self.proxychains_conf):
            print(f"[-] Proxychains config not found at {self.proxychains_conf}")
            print("    Install with: sudo apt install proxychains")
            return False

        with open(self.proxychains_conf, 'r') as f:
            content = f.read()

        required = [
            "dynamic_chain",
            "socks5 127.0.0.1 9050",
            "proxy_dns"
        ]

        missing = [req for req in required if req not in content]
        if missing:
            print(f"[-] Proxychains config missing: {', '.join(missing)}")
            print("    Add these to /etc/proxychains.conf:")
            print("    dynamic_chain\n    socks5 127.0.0.1 9050\n    proxy_dns")
            return False

        print("[+] Proxychains configured correctly")
        return True

    def get_current_ip(self):
        print("[*] Checking current exit IP...")
        ip = self.run_command("proxychains curl -s https://api.ipify.org")
        if ip:
            print(f"[+] Current Tor exit IP: {ip}")
            self.current_ip = ip
            return ip
        else:
            print("[-] Failed to get current IP")
            return None

    def request_new_ip(self):
        print("[*] Requesting new Tor exit IP...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("127.0.0.1", self.tor_control_port))
                s.sendall(b"AUTHENTICATE\r\n")
                response = s.recv(1024)
                if b"250" not in response:
                    print("[-] Tor control port authentication failed")
                    print("    Ensure /etc/tor/torrc contains:")
                    print("    ControlPort 9051\n    CookieAuthentication 0")
                    return False

                s.sendall(b"SIGNAL NEWNYM\r\n")
                response = s.recv(1024)
                if b"250" not in response:
                    print("[-] Failed to request new Tor circuit")
                    return False

                print("[+] New Tor circuit requested")
                time.sleep(5)  # Wait for circuit to establish
                return True
        except Exception as e:
            print(f"[-] Tor control error: {str(e)}")
            return False

    def log_session(self, command, ip=None):
        if not self.log_file:
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, 'a') as f:
            log_entry = f"{timestamp} | IP: {ip or self.current_ip} | Command: {command}\n"
            f.write(log_entry)

    def execute_tool(self, tool_command):
        if self.stealth_mode:
            self.request_new_ip()
            self.get_current_ip()

        print(f"[*] Executing: {tool_command}")
        self.log_session(tool_command)
        os.system(f"proxychains {tool_command}")

    def main(self):
        args = self.parse_arguments()
        
        if args.log:
            self.log_file = args.log
            print(f"[*] Logging to {self.log_file}")
            
        self.stealth_mode = args.stealth

        if not self.check_tor():
            sys.exit(1)

        if not self.check_proxychains_config():
            sys.exit(1)

        if args.check:
            sys.exit(0)

        if args.show_ip or args.stealth or args.new_ip or not any(vars(args).values()):
            self.get_current_ip()

        if args.new_ip:
            if self.request_new_ip():
                self.get_current_ip()

        if args.tool:
            self.execute_tool(args.tool)

if __name__ == "__main__":
    ghost = GhostMode()
    ghost.main()
