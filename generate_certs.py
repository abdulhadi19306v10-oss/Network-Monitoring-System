"""
generate_certs.py — Self-Signed SSL Certificate Generator
==========================================================
Generates a self-signed X.509 certificate and private key for the
Network Monitoring Dashboard server.

Usage:
    python generate_certs.py

Produces:
    server.crt   — PEM-encoded certificate
    server.key   — PEM-encoded RSA private key
"""

import os
import sys
import subprocess
import shutil

CERT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(CERT_DIR, "server.crt")
KEY_FILE = os.path.join(CERT_DIR, "server.key")

SUBJECT = "/C=PK/ST=Punjab/L=Lahore/O=CN-Theory-Project/OU=Dev/CN=localhost"
DAYS_VALID = 365


def generate_with_openssl():
    """Generate certificate using the openssl CLI tool."""
    openssl_path = shutil.which("openssl")
    if not openssl_path:
        return False

    cmd = [
        openssl_path, "req",
        "-x509",
        "-newkey", "rsa:2048",
        "-keyout", KEY_FILE,
        "-out", CERT_FILE,
        "-days", str(DAYS_VALID),
        "-nodes",                    # no passphrase
        "-subj", SUBJECT,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
        print("[+] Certificate generated with openssl CLI.")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"[!] openssl CLI failed: {exc}")
        return False


def generate_with_cryptography():
    """
    Generate certificate using the 'cryptography' Python package.
    This is a fallback if OpenSSL CLI is not available.
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
    except ImportError:
        print("[!] 'cryptography' package not installed.")
        print("    Install it with:  pip install cryptography")
        return False

    # Generate RSA key pair
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Build self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CN-Theory-Project"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Dev"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=DAYS_VALID))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress_from_str("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Write private key
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Write certificate
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("[+] Certificate generated with 'cryptography' library.")
    return True


def ipaddress_from_str(addr: str):
    """Helper to convert IP string to ipaddress object for SAN."""
    import ipaddress
    return ipaddress.IPv4Address(addr)


def main():
    print("=" * 55)
    print("  SSL Certificate Generator — CN Theory Project")
    print("=" * 55)

    # Check if certs already exist
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        answer = input(
            f"\n[?] Certificates already exist:\n"
            f"    {CERT_FILE}\n"
            f"    {KEY_FILE}\n"
            f"    Overwrite? [y/N]: "
        ).strip().lower()
        if answer != "y":
            print("[*] Keeping existing certificates.")
            return

    print("\n[*] Attempting to generate self-signed certificate...")

    # Try openssl first, then cryptography library
    if generate_with_openssl():
        pass
    elif generate_with_cryptography():
        pass
    else:
        print("\n[ERROR] Could not generate certificates.")
        print("        Please install OpenSSL or run:")
        print("            pip install cryptography")
        sys.exit(1)

    print(f"\n[OK] Certificate: {CERT_FILE}")
    print(f"[OK] Key:         {KEY_FILE}")
    print("\nUse these files when launching the server with --ssl.")


if __name__ == "__main__":
    main()
