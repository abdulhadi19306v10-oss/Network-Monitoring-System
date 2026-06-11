"""
server.py — Collaborative Network Monitoring Server
=====================================================
Multi-threaded TCP server with optional TLS/SSL that manages:
  • Client registration & discovery
  • Alert room subscriptions (CPU / Bandwidth / Security)
  • Private messaging between clients
  • File sharing (Base64-encoded payloads)
  • Emergency broadcast alerts

Usage:
    python server.py [--host HOST] [--port PORT] [--ssl]
"""

import argparse
import os
import logging
import shutil
import socket
import ssl
import sys
import threading
import json
import struct
import subprocess
from datetime import datetime

# ---------------------------------------------------------------------------
# Consolidated Shared Utilities & Constants (formerly utils.py)
# ---------------------------------------------------------------------------

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9500
HEADER_SIZE = 4                 # 4-byte big-endian length prefix
MAX_PAYLOAD_SIZE = 50 * 1024 * 1024   # 50 MB hard limit per message
CHUNK_SIZE = 8192               # Read/write chunk size for socket I/O
ENCODING = "utf-8"

# Certificate file paths (relative to project root)
CERT_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_CERT = os.path.join(CERT_DIR, "server.crt")
SERVER_KEY = os.path.join(CERT_DIR, "server.key")

class MsgType:
    CONNECT         = "connect"
    CONNECT_ACK     = "connect_ack"
    DISCONNECT      = "disconnect"
    CLIENT_LIST     = "client_list"
    STATUS_UPDATE   = "status_update"
    JOIN_ROOM       = "join_room"
    LEAVE_ROOM      = "leave_room"
    ROOM_MSG        = "room_msg"
    PRIVATE_MSG     = "private_msg"
    FILE_SHARE      = "file_share"
    FILE_LIST       = "file_list"
    FILE_REQUEST    = "file_request"
    FILE_RESPONSE   = "file_response"
    EMERGENCY       = "emergency"
    ERROR           = "error"

# Available alert rooms
ALERT_ROOMS = ["CPU", "Bandwidth", "Security"]

def setup_logger(name: str, log_file: str = None, level=logging.INFO):
    """Create and return a logger with console + optional file handler."""
    import logging
    logger = logging.getLogger(name)
    logger.setLevel(level)

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File handler (optional)
    if log_file:
        fh = logging.FileHandler(log_file, encoding=ENCODING)
        fh.setLevel(level)
        fh.setFormatter(formatter)
        logger.addHandler(fh)

    return logger

def send_msg(sock: socket.socket, payload: dict) -> None:
    """Serialize payload to JSON, prepend a 4-byte big-endian length prefix, and send."""
    try:
        raw = json.dumps(payload, default=str).encode(ENCODING)
        if len(raw) > MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload size {len(raw)} exceeds maximum {MAX_PAYLOAD_SIZE}")
        header = struct.pack("!I", len(raw))
        sock.sendall(header + raw)
    except (BrokenPipeError, ConnectionResetError, OSError) as exc:
        raise ConnectionError(f"send_msg failed: {exc}") from exc

def recv_msg(sock: socket.socket) -> dict | None:
    """Read a 4-byte prefix, read exact body bytes, decode JSON and return dict."""
    try:
        header_data = _recv_exactly(sock, HEADER_SIZE)
        if header_data is None:
            return None  # clean disconnect

        payload_len = struct.unpack("!I", header_data)[0]
        if payload_len > MAX_PAYLOAD_SIZE:
            raise ValueError(f"Incoming payload size {payload_len} exceeds maximum {MAX_PAYLOAD_SIZE}")

        body_data = _recv_exactly(sock, payload_len)
        if body_data is None:
            return None  # unexpected disconnect mid-message

        return json.loads(body_data.decode(ENCODING))

    except (json.JSONDecodeError, struct.error) as exc:
        raise ConnectionError(f"recv_msg decode error: {exc}") from exc
    except (BrokenPipeError, ConnectionResetError, OSError) as exc:
        raise ConnectionError(f"recv_msg failed: {exc}") from exc

def _recv_exactly(sock: socket.socket, n: int) -> bytes | None:
    """Read exactly n bytes from socket, handling TCP fragmentation."""
    buf = bytearray()
    while len(buf) < n:
        remaining = n - len(buf)
        chunk = sock.recv(min(remaining, CHUNK_SIZE))
        if not chunk:
            if len(buf) == 0:
                return None  # clean close
            raise ConnectionError(f"Connection closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)

def make_error(detail: str) -> dict:
    """Build an ERROR payload."""
    return {
        "type": MsgType.ERROR,
        "detail": detail,
        "timestamp": datetime.now().isoformat(),
    }


# ---------------------------------------------------------------------------
# SSL/TLS Certificate Generation (formerly generate_certs.py)
# ---------------------------------------------------------------------------

def generate_certificates(force=False):
    """Generates self-signed SSL/TLS certificates if they do not exist or if force is True."""
    if not force and os.path.exists(SERVER_CERT) and os.path.exists(SERVER_KEY):
        return True

    print("[*] Generating self-signed SSL/TLS certificates...")
    openssl_path = shutil.which("openssl")
    days_valid = 365
    subject = "/C=PK/ST=Punjab/L=Lahore/O=CN-Theory-Project/OU=Dev/CN=localhost"

    if openssl_path:
        cmd = [
            openssl_path, "req",
            "-x509",
            "-newkey", "rsa:2048",
            "-keyout", SERVER_KEY,
            "-out", SERVER_CERT,
            "-days", str(days_valid),
            "-nodes",
            "-subj", subject,
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            print("[+] Certificates generated using OpenSSL CLI.")
            return True
        except Exception as exc:
            print(f"[!] OpenSSL CLI generation failed: {exc}")

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        import ipaddress

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subj = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CN-Theory-Project"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Dev"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subj)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days_valid))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        with open(SERVER_KEY, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        with open(SERVER_CERT, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print("[+] Certificates generated using 'cryptography' library.")
        return True
    except ImportError:
        print("[ERROR] Neither 'openssl' CLI nor the 'cryptography' library is available.")
        print("        To generate certificates, please install OpenSSL or run: pip install cryptography")
        return False
    except Exception as exc:
        print(f"[ERROR] Cryptography-based generation failed: {exc}")
        return False


# ---------------------------------------------------------------------------
# Server State
# ---------------------------------------------------------------------------

class ClientInfo:
    """Metadata for a single connected client."""

    def __init__(self, sock: socket.socket, address: tuple,
                 username: str = "", hostname: str = "", ip: str = ""):
        self.sock = sock
        self.address = address         # (ip, port) from accept()
        self.username = username
        self.hostname = hostname
        self.ip = ip
        self.rooms: set[str] = set()   # subscribed alert rooms
        self.lock = threading.Lock()   # per-client send lock

    def to_dict(self) -> dict:
        """Serializable summary for CLIENT_LIST broadcasts."""
        return {
            "username": self.username,
            "hostname": self.hostname,
            "ip": self.ip,
            "rooms": list(self.rooms),
        }


class Server:
    """Central Network Monitoring Server."""

    def __init__(self, host: str, port: int, use_ssl: bool = False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl

        # Client registry: maps username -> ClientInfo
        self.clients: dict[str, ClientInfo] = {}
        self.clients_lock = threading.Lock()

        # Shared file registry: list of {filename, username, file_size, file_type, timestamp}
        self.shared_files: list[dict] = []
        self.files_lock = threading.Lock()

        # File data store: maps filename -> base64 data string
        self.file_data_store: dict[str, str] = {}

        self.logger = setup_logger(
            "server",
            log_file=os.path.join(CERT_DIR, "server_logs.txt"),
        )
        self.running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        """Bind, optionally wrap in TLS, and accept connections."""
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((self.host, self.port))
        raw_sock.listen(10)

        if self.use_ssl:
            if not (os.path.exists(SERVER_CERT) and os.path.exists(SERVER_KEY)):
                self.logger.info("SSL enabled but certificates not found. Attempting auto-generation...")
                generate_certificates(force=False)
            
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
            self.server_sock = ctx.wrap_socket(raw_sock, server_side=True)
            self.logger.info("TLS/SSL enabled.")
        else:
            self.server_sock = raw_sock

        self.running = True
        self.logger.info(
            "Server listening on %s:%d (SSL=%s)", self.host, self.port, self.use_ssl
        )

        try:
            while self.running:
                try:
                    client_sock, addr = self.server_sock.accept()
                    self.logger.info("Incoming connection from %s:%d", *addr)
                    t = threading.Thread(
                        target=self._handle_client,
                        args=(client_sock, addr),
                        daemon=True,
                    )
                    t.start()
                except OSError:
                    break
        except KeyboardInterrupt:
            self.logger.info("Shutting down (KeyboardInterrupt).")
        finally:
            self.shutdown()

    def shutdown(self):
        """Gracefully close all connections and the server socket."""
        self.running = False
        with self.clients_lock:
            for info in list(self.clients.values()):
                try:
                    info.sock.close()
                except OSError:
                    pass
            self.clients.clear()
        try:
            self.server_sock.close()
        except OSError:
            pass
        self.logger.info("Server shut down.")

    # ------------------------------------------------------------------
    # Per-client handler
    # ------------------------------------------------------------------

    def _handle_client(self, sock: socket.socket, addr: tuple):
        """Run in a dedicated thread for each connected client."""
        client: ClientInfo | None = None

        try:
            # ---- Wait for CONNECT message ----
            msg = recv_msg(sock)
            if msg is None or msg.get("type") != MsgType.CONNECT:
                self.logger.warning("Bad handshake from %s:%d — dropping.", *addr)
                sock.close()
                return

            username = msg.get("username", f"anon-{addr[1]}")
            hostname = msg.get("hostname", "unknown")
            ip = msg.get("ip", addr[0])

            # Reject duplicate usernames
            with self.clients_lock:
                if username in self.clients:
                    send_msg(sock, make_error(f"Username '{username}' is already taken."))
                    sock.close()
                    return

                client = ClientInfo(sock, addr, username, hostname, ip)
                self.clients[username] = client

            self.logger.info("Client registered: %s (%s / %s)", username, hostname, ip)

            # Send ACK
            send_msg(sock, {
                "type": MsgType.CONNECT_ACK,
                "message": f"Welcome, {username}!",
                "rooms_available": ALERT_ROOMS,
            })

            # Broadcast updated client list
            self._broadcast_client_list()

            # ---- Main message loop ----
            while self.running:
                msg = recv_msg(sock)
                if msg is None:
                    break
                self._route_message(client, msg)

        except ConnectionError as exc:
            self.logger.info("Connection lost (%s): %s", addr, exc)
        except Exception as exc:
            self.logger.exception("Unexpected error for %s: %s", addr, exc)
        finally:
            self._remove_client(client)

    # ------------------------------------------------------------------
    # Message Routing
    # ------------------------------------------------------------------

    def _route_message(self, client: ClientInfo, msg: dict):
        """Dispatch an incoming message to the appropriate handler."""
        msg_type = msg.get("type")

        handlers = {
            MsgType.STATUS_UPDATE:   self._handle_status_update,
            MsgType.JOIN_ROOM:       self._handle_join_room,
            MsgType.LEAVE_ROOM:      self._handle_leave_room,
            MsgType.ROOM_MSG:        self._handle_room_msg,
            MsgType.PRIVATE_MSG:     self._handle_private_msg,
            MsgType.FILE_SHARE:      self._handle_file_share,
            MsgType.FILE_LIST:       self._handle_file_list,
            MsgType.FILE_REQUEST:    self._handle_file_request,
            MsgType.EMERGENCY:       self._handle_emergency,
            MsgType.DISCONNECT:      self._handle_disconnect,
        }

        handler = handlers.get(msg_type)
        if handler:
            handler(client, msg)
        else:
            self.logger.warning(
                "Unknown message type '%s' from %s", msg_type, client.username
            )
            self._safe_send(client, make_error(f"Unknown message type: {msg_type}"))

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _handle_status_update(self, client: ClientInfo, msg: dict):
        """Broadcast a client's metrics to all other clients."""
        self.logger.info(
            "Metrics from %s: %s", client.username, msg.get("metrics")
        )
        self._broadcast(msg, exclude=client.username)

    def _handle_join_room(self, client: ClientInfo, msg: dict):
        """Subscribe a client to an alert room."""
        room = msg.get("room", "").strip()
        if room not in ALERT_ROOMS:
            self._safe_send(client, make_error(f"Invalid room: {room}"))
            return

        client.rooms.add(room)
        self.logger.info("%s joined room [%s]", client.username, room)
        self._safe_send(client, {
            "type": MsgType.JOIN_ROOM,
            "room": room,
            "message": f"You joined room '{room}'.",
        })

        # Notify others in the room
        self._broadcast_to_room(room, {
            "type": MsgType.ROOM_MSG,
            "room": room,
            "username": "SERVER",
            "text": f"{client.username} joined the room.",
            "timestamp": datetime.now().isoformat(),
        }, exclude=client.username)

    def _handle_leave_room(self, client: ClientInfo, msg: dict):
        """Unsubscribe a client from an alert room."""
        room = msg.get("room", "").strip()
        client.rooms.discard(room)
        self.logger.info("%s left room [%s]", client.username, room)
        self._safe_send(client, {
            "type": MsgType.LEAVE_ROOM,
            "room": room,
            "message": f"You left room '{room}'.",
        })

        # Notify others
        self._broadcast_to_room(room, {
            "type": MsgType.ROOM_MSG,
            "room": room,
            "username": "SERVER",
            "text": f"{client.username} left the room.",
            "timestamp": datetime.now().isoformat(),
        }, exclude=client.username)

    def _handle_room_msg(self, client: ClientInfo, msg: dict):
        """Relay a message to all subscribers of a room."""
        room = msg.get("room", "")
        if room not in client.rooms:
            self._safe_send(
                client, make_error(f"You are not subscribed to room '{room}'.")
            )
            return

        self.logger.info(
            "[%s] %s: %s", room, client.username, msg.get("text", "")
        )
        self._broadcast_to_room(room, msg, exclude=client.username)

    def _handle_private_msg(self, client: ClientInfo, msg: dict):
        """Route a private message to the specified recipient."""
        recipient_name = msg.get("recipient", "")
        with self.clients_lock:
            recipient = self.clients.get(recipient_name)

        if recipient is None:
            self._safe_send(
                client, make_error(f"User '{recipient_name}' not found.")
            )
            return

        self.logger.info(
            "PM %s -> %s: %s",
            client.username, recipient_name, msg.get("text", "")[:60],
        )
        self._safe_send(recipient, msg)

    def _handle_file_share(self, client: ClientInfo, msg: dict):
        """Store a shared file and notify all clients."""
        filename = msg.get("filename", "unknown")
        file_data = msg.get("file_data", "")
        file_size = msg.get("file_size", 0)
        file_type = msg.get("file_type", "application/octet-stream")

        # Store file metadata
        file_entry = {
            "filename": filename,
            "username": client.username,
            "file_size": file_size,
            "file_type": file_type,
            "timestamp": datetime.now().isoformat(),
        }

        with self.files_lock:
            self.shared_files.append(file_entry)
            self.file_data_store[filename] = file_data

        self.logger.info(
            "File shared by %s: %s (%d bytes)", client.username, filename, file_size
        )

        # Notify all clients about the new file (without the data itself)
        notification = {
            "type": MsgType.FILE_SHARE,
            "username": client.username,
            "filename": filename,
            "file_size": file_size,
            "file_type": file_type,
            "timestamp": file_entry["timestamp"],
        }
        self._broadcast(notification, exclude=client.username)

        # Send updated file list to all
        self._broadcast_file_list()

    def _handle_file_list(self, client: ClientInfo, _msg: dict):
        """Send the current shared file list to the requesting client."""
        with self.files_lock:
            file_list = list(self.shared_files)

        self._safe_send(client, {
            "type": MsgType.FILE_LIST,
            "files": file_list,
        })

    def _handle_file_request(self, client: ClientInfo, msg: dict):
        """Send the requested file data back to the client."""
        filename = msg.get("filename", "")

        with self.files_lock:
            file_data = self.file_data_store.get(filename)

        if file_data is None:
            self._safe_send(client, make_error(f"File '{filename}' not found."))
            return

        self.logger.info(
            "File download: %s requested '%s'", client.username, filename
        )
        self._safe_send(client, {
            "type": MsgType.FILE_RESPONSE,
            "filename": filename,
            "file_data": file_data,
        })

    def _handle_emergency(self, client: ClientInfo, msg: dict):
        """Broadcast an emergency alert to ALL connected clients."""
        self.logger.warning(
            "EMERGENCY from %s: %s", client.username, msg.get("message", "")
        )
        # Send to everyone including the sender (for confirmation)
        self._broadcast(msg)

    def _handle_disconnect(self, client: ClientInfo, _msg: dict):
        """Handle a graceful disconnect request."""
        raise ConnectionError("Client requested disconnect.")

    # ------------------------------------------------------------------
    # Broadcasting
    # ------------------------------------------------------------------

    def _broadcast(self, msg: dict, exclude: str = None):
        """Send *msg* to all connected clients, optionally excluding one."""
        with self.clients_lock:
            targets = [
                c for name, c in self.clients.items() if name != exclude
            ]
        for c in targets:
            self._safe_send(c, msg)

    def _broadcast_to_room(self, room: str, msg: dict, exclude: str = None):
        """Send *msg* to all clients subscribed to *room*."""
        with self.clients_lock:
            targets = [
                c for name, c in self.clients.items()
                if room in c.rooms and name != exclude
            ]
        for c in targets:
            self._safe_send(c, msg)

    def _broadcast_client_list(self):
        """Send an updated client list to every connected client."""
        with self.clients_lock:
            client_list = [c.to_dict() for c in self.clients.values()]

        msg = {
            "type": MsgType.CLIENT_LIST,
            "clients": client_list,
        }
        self._broadcast(msg)

    def _broadcast_file_list(self):
        """Send an updated file list to every connected client."""
        with self.files_lock:
            file_list = list(self.shared_files)

        msg = {
            "type": MsgType.FILE_LIST,
            "files": file_list,
        }
        self._broadcast(msg)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _safe_send(self, client: ClientInfo, msg: dict):
        """Thread-safe send; removes client on failure."""
        try:
            with client.lock:
                send_msg(client.sock, msg)
        except ConnectionError:
            self._remove_client(client)

    def _remove_client(self, client: ClientInfo | None):
        """Unregister a client and broadcast the updated list."""
        if client is None:
            return

        removed = False
        with self.clients_lock:
            if client.username in self.clients:
                del self.clients[client.username]
                removed = True

        if removed:
            self.logger.info("Client disconnected: %s", client.username)
            try:
                client.sock.close()
            except OSError:
                pass
            self._broadcast_client_list()


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Collaborative Network Monitoring Server"
    )
    parser.add_argument(
        "--host", default=DEFAULT_HOST,
        help=f"Bind address (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"Bind port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--ssl", action="store_true",
        help="Enable TLS/SSL encryption (requires server.crt & server.key)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    server = Server(host=args.host, port=args.port, use_ssl=args.ssl)

    print("=" * 55)
    print("  Collaborative Network Monitoring Server")
    print("=" * 55)
    print(f"  Host : {args.host}")
    print(f"  Port : {args.port}")
    print(f"  SSL  : {'Enabled' if args.ssl else 'Disabled'}")
    print("=" * 55)
    print("  Press Ctrl+C to stop.\n")

    server.start()


if __name__ == "__main__":
    main()
