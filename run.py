"""
run.py — Startup Launcher Script
=================================
Boots the Network Nexus Server, the Client Bridge, and
automatically opens the dashboard page in the default web browser.

Handles graceful termination of both subprocesses when closed via Ctrl+C.

Usage:
    python run.py [--ssl]
"""

import argparse
import os
import subprocess
import sys
import time
import webbrowser

import socket

def parse_args():
    parser = argparse.ArgumentParser(description="Launcher for Network Nexus")
    parser.add_argument(
        "--ssl", action="store_true",
        help="Enable TLS/SSL encryption for server and client connection",
    )
    return parser.parse_args()

def main():
    args = parse_args()
    cwd = os.path.dirname(os.path.abspath(__file__))

    server_script = os.path.join(cwd, "server.py")
    client_script = os.path.join(cwd, "client.py")

    server_cmd = [sys.executable, server_script]
    client_cmd = [sys.executable, client_script]

    if args.ssl:
        server_cmd.append("--ssl")
        # Note: client.py receives SSL preference from the UI checkbox, 
        # but the launcher will print that SSL mode is prepared.

    # Detect local LAN IP
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "127.0.0.1"

    print("=" * 60)
    print("  Starting Network Nexus Launcher")
    print("=" * 60)

    # 1. Start Server Subprocess
    print("[*] Starting Monitoring Server...")
    server_proc = subprocess.Popen(
        server_cmd,
        cwd=cwd,
        stdout=subprocess.DEVNULL, # keep console clean, logs write to server_logs.txt
        stderr=subprocess.STDOUT
    )
    time.sleep(1.0) # wait for server port binding

    # 2. Start Client Bridge Subprocess
    print("[*] Starting Web Client Bridge...")
    client_proc = subprocess.Popen(
        client_cmd,
        cwd=cwd,
        stdout=subprocess.DEVNULL, # keep console clean
        stderr=subprocess.STDOUT
    )
    time.sleep(1.5) # wait for web server boot

    # 3. Open Web Page
    url_local = "http://localhost:8080"
    url_lan = f"http://{local_ip}:8080"
    print(f"[+] Opening browser to local dashboard: {url_local}")
    print(f"[+] LAN accessibility enabled! Your friends on the same network can access it at:")
    print(f"    --> {url_lan}")
    print(f"    (Make sure your firewall allows python connections on port 8080!)")
    webbrowser.open(url_local)

    print("\n[SUCCESS] All services are running.")
    print("Press Ctrl+C in this terminal to terminate all processes.\n")

    try:
        while True:
            # Check if any process died unexpectedly
            if server_proc.poll() is not None:
                print("[!] Server process terminated unexpectedly.")
                break
            if client_proc.poll() is not None:
                print("[!] Client process terminated unexpectedly.")
                break
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Stopping all services...")
    finally:
        # Graceful cleanup
        if client_proc.poll() is None:
            client_proc.terminate()
            client_proc.wait()
            print("[-] Stopped Client Bridge.")
        if server_proc.poll() is None:
            server_proc.terminate()
            server_proc.wait()
            print("[-] Stopped Monitoring Server.")
        print("=" * 60)
        print("  Services successfully cleaned up.")
        print("=" * 60)

if __name__ == "__main__":
    main()
