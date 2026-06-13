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

        # SQLite Database initialization
        self.db_path = os.path.join(CERT_DIR, "server_db.sqlite")
        self._init_db()
        self._load_data_from_db()

    def _init_db(self):
        """Create database tables if they do not exist."""
        import sqlite3
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS shared_files (
                    filename TEXT PRIMARY KEY,
                    username TEXT,
                    file_size INTEGER,
                    file_type TEXT,
                    file_data TEXT,
                    timestamp TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS emergency_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    message TEXT,
                    timestamp TEXT
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error("Failed to initialize SQLite database: %s", e)

    def _load_data_from_db(self):
        """Load persistent shared files from database on startup."""
        import sqlite3
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT filename, username, file_size, file_type, timestamp FROM shared_files")
            rows = cursor.fetchall()
            for row in rows:
                self.shared_files.append({
                    "filename": row[0],
                    "username": row[1],
                    "file_size": row[2],
                    "file_type": row[3],
                    "timestamp": row[4],
                })
            
            cursor.execute("SELECT filename, file_data FROM shared_files")
            data_rows = cursor.fetchall()
            for row in data_rows:
                self.file_data_store[row[0]] = row[1]
                
            conn.close()
            self.logger.info("Loaded %d shared files from SQLite database.", len(self.shared_files))
        except Exception as e:
            self.logger.error("Failed to load data from SQLite database: %s", e)

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

        # Start Server Dashboard Web Interface on Port 9600
        self.dashboard_port = 9600
        self.logger.info("Starting Server Dashboard web interface on http://localhost:%d...", self.dashboard_port)
        t_dash = threading.Thread(
            target=run_flask_dashboard,
            args=(self, self.dashboard_port),
            daemon=True
        )
        t_dash.start()

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
            # Dynamic TLS/SSL auto-detection
            sock.settimeout(2.0)
            try:
                peek_bytes = sock.recv(4, socket.MSG_PEEK)
                if len(peek_bytes) >= 2 and peek_bytes[0] == 0x16 and peek_bytes[1] == 0x03:
                    self.logger.info("Dynamic TLS connection detected from %s:%d. Wrapping socket.", *addr)
                    if not (os.path.exists(SERVER_CERT) and os.path.exists(SERVER_KEY)):
                        self.logger.info("SSL enabled but certificates not found. Attempting auto-generation...")
                        generate_certificates(force=False)
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
                    sock = ctx.wrap_socket(sock, server_side=True)
            except Exception as e:
                self.logger.warning("Dynamic SSL detection / handshake failed for %s:%d: %s", addr[0], addr[1], e)
                sock.close()
                return
            finally:
                sock.settimeout(None)

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
            # Check if file already exists in metadata cache, update it
            existing_idx = next((i for i, f in enumerate(self.shared_files) if f["filename"] == filename), None)
            if existing_idx is not None:
                self.shared_files[existing_idx] = file_entry
            else:
                self.shared_files.append(file_entry)
            self.file_data_store[filename] = file_data

            # Save to SQLite database persistently
            try:
                import sqlite3
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO shared_files (filename, username, file_size, file_type, file_data, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (filename, client.username, file_size, file_type, file_data, file_entry["timestamp"]))
                conn.commit()
                conn.close()
            except Exception as e:
                self.logger.error("Failed to persist shared file into database: %s", e)

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
        """Broadcast an emergency alert to ALL connected clients and save to DB."""
        self.logger.warning(
            "EMERGENCY from %s: %s", client.username, msg.get("message", "")
        )
        
        # Save to SQLite database persistently
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO emergency_logs (username, message, timestamp)
                VALUES (?, ?, ?)
            """, (client.username, msg.get("message", ""), datetime.now().isoformat()))
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error("Failed to persist emergency alert into database: %s", e)
            
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
# Server Dashboard Flask Web Service
# ---------------------------------------------------------------------------

DASHBOARD_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Nexus Server Console</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-color: #0b0f19;
            --panel-bg: rgba(17, 24, 39, 0.7);
            --border-color: rgba(255, 255, 255, 0.08);
            --accent-teal: #00f2fe;
            --accent-cyan: #4facfe;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --alert-red: #ef4444;
            --alert-green: #10b981;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: 'Outfit', sans-serif;
            background: radial-gradient(circle at top right, #1e1b4b, var(--bg-color) 80%);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 2rem;
            overflow-x: hidden;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            backdrop-filter: blur(12px);
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            padding: 1.5rem 2rem;
            border-radius: 16px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
        }
        .header-title h1 {
            font-size: 1.8rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--accent-teal), var(--accent-cyan));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.5px;
        }
        .header-title p {
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin-top: 4px;
        }
        .server-badge {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid var(--alert-green);
            color: var(--alert-green);
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-weight: 600;
            font-size: 0.85rem;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .pulse-dot {
            width: 8px;
            height: 8px;
            background-color: var(--alert-green);
            border-radius: 50%;
            animation: pulse 1.5s infinite;
        }
        @keyframes pulse {
            0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
            70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
            100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            backdrop-filter: blur(12px);
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            padding: 1.5rem;
            border-radius: 16px;
            box-shadow: 0 4px 20px 0 rgba(0, 0, 0, 0.15);
            display: flex;
            flex-direction: column;
        }
        .stat-label {
            font-size: 0.85rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 0.5rem;
        }
        .stat-value {
            font-size: 1.75rem;
            font-weight: 800;
            color: var(--text-primary);
        }
        .stat-value.teal {
            color: var(--accent-teal);
            text-shadow: 0 0 10px rgba(0, 242, 254, 0.2);
        }

        .main-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 2rem;
            margin-bottom: 2rem;
        }
        @media (max-width: 1024px) {
            .main-grid {
                grid-template-columns: 1fr;
            }
        }
        
        .panel {
            backdrop-filter: blur(12px);
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.2);
            margin-bottom: 2rem;
        }
        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.25rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.75rem;
        }
        .panel-title {
            font-size: 1.2rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .panel-title svg {
            color: var(--accent-teal);
        }
        
        .table-container {
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }
        th {
            color: var(--text-secondary);
            font-size: 0.85rem;
            font-weight: 600;
            padding: 0.75rem 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        td {
            padding: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.03);
            font-size: 0.95rem;
            color: var(--text-primary);
        }
        tr:hover td {
            background: rgba(255, 255, 255, 0.02);
        }
        .empty-row {
            text-align: center;
            color: var(--text-secondary);
            padding: 2rem;
        }
        
        .room-badge {
            background: rgba(79, 172, 254, 0.15);
            border: 1px solid var(--accent-cyan);
            color: var(--text-primary);
            padding: 0.2rem 0.5rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-right: 4px;
            display: inline-block;
        }
        .room-badge.CPU {
            background: rgba(239, 68, 68, 0.15);
            border-color: rgba(239, 68, 68, 0.5);
        }
        .room-badge.Bandwidth {
            background: rgba(16, 185, 129, 0.15);
            border-color: rgba(16, 185, 129, 0.5);
        }
        .room-badge.Security {
            background: rgba(245, 158, 11, 0.15);
            border-color: rgba(245, 158, 11, 0.5);
        }

        .console-container {
            background: #05070c;
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 1rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            line-height: 1.5;
            height: 350px;
            overflow-y: auto;
            white-space: pre-wrap;
            color: #d1d5db;
        }
        .log-entry {
            margin-bottom: 4px;
        }
        .log-entry.info { color: #38bdf8; }
        .log-entry.warn { color: #f59e0b; }
        .log-entry.error { color: #ef4444; }
        
        .toggle-container {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }
        .switch {
            position: relative;
            display: inline-block;
            width: 44px;
            height: 22px;
        }
        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        .slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #374151;
            transition: .3s;
            border-radius: 22px;
        }
        .slider:before {
            position: absolute;
            content: "";
            height: 16px;
            width: 16px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: .3s;
            border-radius: 50%;
        }
        input:checked + .slider {
            background-color: var(--accent-teal);
        }
        input:checked + .slider:before {
            transform: translateX(22px);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>Network Nexus</h1>
                <p>Collaborative Server Operations & Status Console</p>
            </div>
            <div class="server-badge">
                <span class="pulse-dot"></span>
                <span>SERVER RUNNING</span>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <span class="stat-label">Binding Address</span>
                <span class="stat-value teal" id="server-host">-</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Listening Port</span>
                <span class="stat-value teal" id="server-port">-</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Encryption Mode</span>
                <span class="stat-value" id="server-ssl">-</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Connected Clients</span>
                <span class="stat-value teal" id="client-count">0</span>
            </div>
            <div class="stat-card">
                <span class="stat-label">Shared Logs/Files</span>
                <span class="stat-value teal" id="files-count">0</span>
            </div>
        </div>

        <div class="main-grid">
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>
                        Registered Client Nodes
                    </span>
                    <div class="toggle-container">
                        <span>Auto Refresh</span>
                        <label class="switch">
                            <input type="checkbox" id="auto-refresh" checked>
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Hostname</th>
                                <th>IP Address</th>
                                <th>Active Alert Subscriptions</th>
                            </tr>
                        </thead>
                        <tbody id="clients-tbody">
                            <tr>
                                <td colspan="4" class="empty-row">No active client nodes connected.</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                        Shared Incident Evidence
                    </span>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Filename</th>
                                <th>Sender</th>
                                <th>Size</th>
                            </tr>
                        </thead>
                        <tbody id="files-tbody">
                            <tr>
                                <td colspan="3" class="empty-row">No files shared yet.</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="panel">
            <div class="panel-header">
                <span class="panel-title">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
                    Live Console Log Stream
                </span>
            </div>
            <div class="console-container" id="log-console">Loading server logs...</div>
        </div>
    </div>

    <script>
        const hostEl = document.getElementById('server-host');
        const portEl = document.getElementById('server-port');
        const sslEl = document.getElementById('server-ssl');
        const countEl = document.getElementById('client-count');
        const filesCountEl = document.getElementById('files-count');
        const clientsTbody = document.getElementById('clients-tbody');
        const filesTbody = document.getElementById('files-tbody');
        const consoleEl = document.getElementById('log-console');
        const autoRefreshEl = document.getElementById('auto-refresh');

        let intervalId = null;

        async function updateStatus() {
            try {
                const res = await fetch('/api/status');
                if (!res.ok) throw new Error('API server unreachable');
                const data = await res.json();
                
                // Set metadata
                hostEl.textContent = data.host;
                portEl.textContent = data.port;
                sslEl.textContent = data.use_ssl ? 'TLS/SSL (Encrypted)' : 'Plaintext (Unencrypted)';
                sslEl.style.color = data.use_ssl ? 'var(--alert-green)' : 'var(--text-secondary)';
                
                // Set counts
                countEl.textContent = data.clients.length;
                filesCountEl.textContent = data.shared_files.length;
                
                // Render clients
                if (data.clients.length === 0) {
                    clientsTbody.innerHTML = '<tr><td colspan="4" class="empty-row">No active client nodes connected.</td></tr>';
                } else {
                    clientsTbody.innerHTML = data.clients.map(c => `
                        <tr>
                            <td style="font-weight: 600; color: var(--accent-teal);">\${escapeHtml(c.username)}</td>
                            <td>\${escapeHtml(c.hostname)}</td>
                            <td>\${escapeHtml(c.ip)}</td>
                            <td>\${c.rooms.length === 0 ? '<span style="color: var(--text-secondary);">None</span>' : c.rooms.map(r => \`<span class="room-badge \${r}">\${r}</span>\`).join('')}</td>
                        </tr>
                    `).join('');
                }
                
                // Render files
                if (data.shared_files.length === 0) {
                    filesTbody.innerHTML = '<tr><td colspan="3" class="empty-row">No files shared yet.</td></tr>';
                } else {
                    filesTbody.innerHTML = data.shared_files.map(f => `
                        <tr>
                            <td style="font-weight: 500; font-family: monospace;">\${escapeHtml(f.filename)}</td>
                            <td>\${escapeHtml(f.username)}</td>
                            <td style="color: var(--text-secondary);">\${formatBytes(f.file_size)}</td>
                        </tr>
                    `).join('');
                }
                
                // Render logs
                const wasScrolledToBottom = consoleEl.scrollHeight - consoleEl.clientHeight <= consoleEl.scrollTop + 50;
                
                consoleEl.innerHTML = data.logs.map(log => {
                    let logClass = 'info';
                    if (log.includes('[WARNING]')) logClass = 'warn';
                    if (log.includes('[ERROR]') || log.includes('[!]')) logClass = 'error';
                    return \`<div class="log-entry \${logClass}">\${escapeHtml(log)}</div>\`;
                }).join('');
                
                if (wasScrolledToBottom) {
                    consoleEl.scrollTop = consoleEl.scrollHeight;
                }
            } catch (err) {
                console.error(err);
                consoleEl.innerHTML = \`<div class="log-entry error">[Console Error] Failed to update server status: \${err.message}</div>\`;
            }
        }

        function escapeHtml(str) {
            return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        function formatBytes(bytes, decimals = 2) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
        }

        function setupAutoRefresh() {
            if (autoRefreshEl.checked) {
                updateStatus();
                intervalId = setInterval(updateStatus, 2000);
            } else {
                if (intervalId) clearInterval(intervalId);
            }
        }

        autoRefreshEl.addEventListener('change', setupAutoRefresh);
        
        // Initial setup
        updateStatus();
        intervalId = setInterval(updateStatus, 2000);
    </script>
</body>
</html>
"""

def run_flask_dashboard(server_instance, port):
    """Starts the Flask web console on a daemon thread."""
    from flask import Flask, jsonify, render_template_string
    import logging
    
    app = Flask("server_dashboard")
    
    # Silence Flask console messages to avoid polluting terminal logs
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML_TEMPLATE)

    @app.route("/api/status")
    def status():
        clients_data = []
        with server_instance.clients_lock:
            for name, c_info in server_instance.clients.items():
                clients_data.append(c_info.to_dict())

        with server_instance.files_lock:
            files_data = list(server_instance.shared_files)

        log_file_path = os.path.join(CERT_DIR, "server_logs.txt")
        logs = []
        if os.path.exists(log_file_path):
            try:
                with open(log_file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    logs = [line.strip() for line in lines[-50:]]
            except Exception as e:
                logs = [f"Failed to read server logs: {e}"]
        else:
            logs = ["Log file does not exist yet."]

        # Read emergency logs from SQLite to display in the dashboard logs if they exist
        db_emergencies = []
        try:
            import sqlite3
            if os.path.exists(server_instance.db_path):
                conn = sqlite3.connect(server_instance.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT username, message, timestamp FROM emergency_logs ORDER BY id DESC LIMIT 10")
                rows = cursor.fetchall()
                for r in rows:
                    db_emergencies.append(f"[{r[2]}] [EMERGENCY] {r[0]}: {r[1]}")
                conn.close()
        except Exception:
            pass

        # Prepend DB emergencies to log listing for display
        logs = db_emergencies + logs

        return jsonify({
            "host": server_instance.host,
            "port": server_instance.port,
            "use_ssl": server_instance.use_ssl,
            "clients": clients_data,
            "shared_files": files_data,
            "logs": logs
        })

    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)


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
