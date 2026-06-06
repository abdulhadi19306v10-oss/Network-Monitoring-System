"""
utils.py — Shared Protocol Utilities
=====================================
Provides length-prefixed JSON messaging over TCP sockets, shared constants,
and helper functions used by both the server and client components of the
Collaborative Network Monitoring and Alert Dashboard.
"""

import json
import struct
import socket
import logging
import os
from datetime import datetime

# ---------------------------------------------------------------------------
# Constants
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

# ---------------------------------------------------------------------------
# Message Types
# ---------------------------------------------------------------------------
class MsgType:
    """Enumerates all message types in the protocol."""
    # Connection lifecycle
    CONNECT         = "connect"
    CONNECT_ACK     = "connect_ack"
    DISCONNECT      = "disconnect"

    # Client list management
    CLIENT_LIST     = "client_list"

    # Metrics / status
    STATUS_UPDATE   = "status_update"

    # Alert rooms
    JOIN_ROOM       = "join_room"
    LEAVE_ROOM      = "leave_room"
    ROOM_MSG        = "room_msg"

    # Private messaging
    PRIVATE_MSG     = "private_msg"

    # File sharing
    FILE_SHARE      = "file_share"
    FILE_LIST       = "file_list"
    FILE_REQUEST    = "file_request"
    FILE_RESPONSE   = "file_response"

    # Emergency
    EMERGENCY       = "emergency"

    # Error
    ERROR           = "error"

# Available alert rooms
ALERT_ROOMS = ["CPU", "Bandwidth", "Security"]

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
def setup_logger(name: str, log_file: str = None, level=logging.INFO) -> logging.Logger:
    """
    Create and return a logger with console + optional file handler.
    """
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

# ---------------------------------------------------------------------------
# Protocol Helpers
# ---------------------------------------------------------------------------
def send_msg(sock: socket.socket, payload: dict) -> None:
    """
    Serialize *payload* to JSON, prepend a 4-byte big-endian length header,
    and send over *sock*.

    Raises ConnectionError on failure.
    """
    try:
        raw = json.dumps(payload, default=str).encode(ENCODING)
        if len(raw) > MAX_PAYLOAD_SIZE:
            raise ValueError(
                f"Payload size {len(raw)} exceeds maximum {MAX_PAYLOAD_SIZE}"
            )
        header = struct.pack("!I", len(raw))
        sock.sendall(header + raw)
    except (BrokenPipeError, ConnectionResetError, OSError) as exc:
        raise ConnectionError(f"send_msg failed: {exc}") from exc


def recv_msg(sock: socket.socket) -> dict | None:
    """
    Read a 4-byte big-endian length header, then read exactly that many bytes,
    decode JSON, and return the resulting dict.

    Returns None if the remote end closed the connection cleanly.
    Raises ConnectionError on unexpected failures.
    """
    try:
        # --- Read header ---
        header_data = _recv_exactly(sock, HEADER_SIZE)
        if header_data is None:
            return None  # clean disconnect

        payload_len = struct.unpack("!I", header_data)[0]
        if payload_len > MAX_PAYLOAD_SIZE:
            raise ValueError(
                f"Incoming payload size {payload_len} exceeds maximum {MAX_PAYLOAD_SIZE}"
            )

        # --- Read body ---
        body_data = _recv_exactly(sock, payload_len)
        if body_data is None:
            return None  # unexpected disconnect mid-message

        return json.loads(body_data.decode(ENCODING))

    except (json.JSONDecodeError, struct.error) as exc:
        raise ConnectionError(f"recv_msg decode error: {exc}") from exc
    except (BrokenPipeError, ConnectionResetError, OSError) as exc:
        raise ConnectionError(f"recv_msg failed: {exc}") from exc


def _recv_exactly(sock: socket.socket, n: int) -> bytes | None:
    """
    Read exactly *n* bytes from *sock*, handling TCP fragmentation.
    Returns None if the connection is closed before any data is read.
    """
    buf = bytearray()
    while len(buf) < n:
        remaining = n - len(buf)
        chunk = sock.recv(min(remaining, CHUNK_SIZE))
        if not chunk:
            if len(buf) == 0:
                return None  # clean close
            raise ConnectionError(
                f"Connection closed after {len(buf)}/{n} bytes"
            )
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Message Factory Helpers
# ---------------------------------------------------------------------------
def make_connect_msg(username: str, hostname: str, ip: str) -> dict:
    """Build a CONNECT message payload."""
    return {
        "type": MsgType.CONNECT,
        "username": username,
        "hostname": hostname,
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
    }


def make_status_update(username: str, metrics: dict) -> dict:
    """Build a STATUS_UPDATE message with simulated metrics."""
    return {
        "type": MsgType.STATUS_UPDATE,
        "username": username,
        "metrics": metrics,
        "timestamp": datetime.now().isoformat(),
    }


def make_room_msg(username: str, room: str, text: str) -> dict:
    """Build a ROOM_MSG payload."""
    return {
        "type": MsgType.ROOM_MSG,
        "username": username,
        "room": room,
        "text": text,
        "timestamp": datetime.now().isoformat(),
    }


def make_private_msg(sender: str, recipient: str, text: str) -> dict:
    """Build a PRIVATE_MSG payload."""
    return {
        "type": MsgType.PRIVATE_MSG,
        "sender": sender,
        "recipient": recipient,
        "text": text,
        "timestamp": datetime.now().isoformat(),
    }


def make_file_share(username: str, filename: str, file_data_b64: str,
                     file_size: int, file_type: str = "application/octet-stream") -> dict:
    """Build a FILE_SHARE payload (file content Base64-encoded)."""
    return {
        "type": MsgType.FILE_SHARE,
        "username": username,
        "filename": filename,
        "file_data": file_data_b64,
        "file_size": file_size,
        "file_type": file_type,
        "timestamp": datetime.now().isoformat(),
    }


def make_emergency(username: str, message: str) -> dict:
    """Build an EMERGENCY broadcast payload."""
    return {
        "type": MsgType.EMERGENCY,
        "username": username,
        "message": message,
        "timestamp": datetime.now().isoformat(),
    }


def make_error(detail: str) -> dict:
    """Build an ERROR payload."""
    return {
        "type": MsgType.ERROR,
        "detail": detail,
        "timestamp": datetime.now().isoformat(),
    }
