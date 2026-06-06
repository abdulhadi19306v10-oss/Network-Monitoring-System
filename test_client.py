"""
test_client.py — Automated CLI Test Client
============================================
Spawns multiple virtual clients to exercise the server's features:
  1. Multi-client connection & discovery
  2. Alert room join / messaging / leave
  3. Private messaging
  4. File sharing (upload + download)
  5. Emergency broadcast

Usage:
    # Start the server first:
    #   python server.py [--ssl]
    #
    # Then run this test:
    #   python test_client.py [--host HOST] [--port PORT] [--ssl]
"""

import argparse
import base64
import os
import socket
import ssl
import sys
import threading
import time
from datetime import datetime

from utils import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    SERVER_CERT,
    MsgType,
    send_msg,
    recv_msg,
    make_connect_msg,
    make_status_update,
    make_room_msg,
    make_private_msg,
    make_file_share,
    make_emergency,
    setup_logger,
)

logger = setup_logger("test_client")

# ---------------------------------------------------------------------------
# Virtual Client
# ---------------------------------------------------------------------------

class VirtualClient:
    """Lightweight client that connects to the server and collects messages."""

    def __init__(self, host: str, port: int, username: str, use_ssl: bool = False):
        self.host = host
        self.port = port
        self.username = username
        self.use_ssl = use_ssl
        self.sock: socket.socket | None = None
        self.inbox: list[dict] = []
        self.inbox_lock = threading.Lock()
        self.connected = False
        self._receiver_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    # -- Connection --

    def connect(self):
        """Open a TCP connection and send the CONNECT handshake."""
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if self.use_ssl:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_verify_locations(SERVER_CERT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
            self.sock = ctx.wrap_socket(raw, server_hostname="localhost")
        else:
            self.sock = raw

        self.sock.connect((self.host, self.port))

        # Send CONNECT
        send_msg(self.sock, make_connect_msg(
            username=self.username,
            hostname=f"host-{self.username}",
            ip=self.host,
        ))

        # Start receiver thread
        self._stop_event.clear()
        self._receiver_thread = threading.Thread(
            target=self._receive_loop, daemon=True
        )
        self._receiver_thread.start()

        # Wait briefly for CONNECT_ACK
        ack = self.wait_for(MsgType.CONNECT_ACK, timeout=5)
        if ack:
            self.connected = True
            logger.info("[%s] Connected: %s", self.username, ack.get("message"))
        else:
            logger.error("[%s] Did not receive CONNECT_ACK!", self.username)

    def disconnect(self):
        """Close the connection."""
        self._stop_event.set()
        if self.sock:
            try:
                send_msg(self.sock, {"type": MsgType.DISCONNECT})
            except Exception:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
        self.connected = False
        logger.info("[%s] Disconnected.", self.username)

    # -- Receiver --

    def _receive_loop(self):
        """Background thread collecting messages from the server."""
        while not self._stop_event.is_set():
            try:
                msg = recv_msg(self.sock)
                if msg is None:
                    break
                with self.inbox_lock:
                    self.inbox.append(msg)
            except ConnectionError:
                break
            except Exception as exc:
                logger.debug("[%s] Receiver error: %s", self.username, exc)
                break

    # -- Message helpers --

    def send(self, payload: dict):
        """Send a raw payload dict."""
        send_msg(self.sock, payload)

    def wait_for(self, msg_type: str, timeout: float = 3.0,
                 match: dict = None) -> dict | None:
        """
        Poll the inbox for a message matching *msg_type* (and optional
        key-value pairs in *match*) within *timeout* seconds.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.inbox_lock:
                for i, m in enumerate(self.inbox):
                    if m.get("type") != msg_type:
                        continue
                    if match and not all(m.get(k) == v for k, v in match.items()):
                        continue
                    self.inbox.pop(i)
                    return m
            time.sleep(0.05)
        return None

    def drain(self, msg_type: str = None) -> list[dict]:
        """Remove and return all messages, optionally filtered by type."""
        with self.inbox_lock:
            if msg_type:
                kept, drained = [], []
                for m in self.inbox:
                    (drained if m.get("type") == msg_type else kept).append(m)
                self.inbox = kept
                return drained
            else:
                drained = list(self.inbox)
                self.inbox.clear()
                return drained


# ---------------------------------------------------------------------------
# Test Scenarios
# ---------------------------------------------------------------------------

class TestRunner:
    """Runs all Phase 1 test scenarios."""

    def __init__(self, host: str, port: int, use_ssl: bool):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.passed = 0
        self.failed = 0

    def _assert(self, condition: bool, label: str):
        if condition:
            self.passed += 1
            logger.info("  [PASS] %s", label)
        else:
            self.failed += 1
            logger.error("  [FAIL] %s", label)

    def run_all(self):
        print("\n" + "=" * 60)
        print("  Phase 1 — Automated Backend Test Suite")
        print("=" * 60 + "\n")

        alice = VirtualClient(self.host, self.port, "Alice", self.use_ssl)
        bob   = VirtualClient(self.host, self.port, "Bob",   self.use_ssl)
        carol = VirtualClient(self.host, self.port, "Carol", self.use_ssl)

        try:
            # --- 1. Multi-client connection ---
            self._test_connections(alice, bob, carol)

            # --- 2. Client discovery ---
            self._test_client_list(alice, bob, carol)

            # --- 3. Room join & messaging ---
            self._test_rooms(alice, bob, carol)

            # --- 4. Private messaging ---
            self._test_private_msg(alice, bob, carol)

            # --- 5. Status update broadcast ---
            self._test_status_update(alice, bob, carol)

            # --- 6. File sharing ---
            self._test_file_sharing(alice, bob, carol)

            # --- 7. Emergency broadcast ---
            self._test_emergency(alice, bob, carol)

        finally:
            alice.disconnect()
            bob.disconnect()
            carol.disconnect()

        # --- Summary ---
        total = self.passed + self.failed
        print("\n" + "=" * 60)
        print(f"  Results: {self.passed}/{total} passed, {self.failed} failed")
        print("=" * 60 + "\n")

        return self.failed == 0

    # ------------------------------------------------------------------

    def _test_connections(self, alice, bob, carol):
        print("\n--- Test 1: Multi-Client Connection ---")
        alice.connect()
        self._assert(alice.connected, "Alice connected")
        bob.connect()
        self._assert(bob.connected, "Bob connected")
        carol.connect()
        self._assert(carol.connected, "Carol connected")

    def _test_client_list(self, alice, bob, carol):
        print("\n--- Test 2: Client Discovery ---")
        time.sleep(0.5)  # let broadcasts settle

        # Drain all CLIENT_LIST messages and check the latest one
        lists_a = alice.drain(MsgType.CLIENT_LIST)
        if lists_a:
            latest = lists_a[-1]
            names = [c["username"] for c in latest.get("clients", [])]
            self._assert("Bob" in names, "Alice sees Bob in client list")
            self._assert("Carol" in names, "Alice sees Carol in client list")
        else:
            self._assert(False, "Alice received a CLIENT_LIST")

    def _test_rooms(self, alice, bob, carol):
        print("\n--- Test 3: Alert Rooms ---")

        # Alice and Bob join CPU room
        alice.send({"type": MsgType.JOIN_ROOM, "room": "CPU"})
        bob.send({"type": MsgType.JOIN_ROOM, "room": "CPU"})
        time.sleep(0.3)

        ack_a = alice.wait_for(MsgType.JOIN_ROOM, match={"room": "CPU"})
        self._assert(ack_a is not None, "Alice joined CPU room")

        ack_b = bob.wait_for(MsgType.JOIN_ROOM, match={"room": "CPU"})
        self._assert(ack_b is not None, "Bob joined CPU room")

        # Drain join notifications
        alice.drain(MsgType.ROOM_MSG)
        bob.drain(MsgType.ROOM_MSG)
        carol.drain(MsgType.ROOM_MSG)

        # Alice sends a message to CPU room
        alice.send(make_room_msg("Alice", "CPU", "CPU usage is at 95%!"))
        time.sleep(0.3)

        bob_got = bob.wait_for(MsgType.ROOM_MSG, match={"room": "CPU"})
        self._assert(
            bob_got is not None and bob_got.get("username") == "Alice",
            "Bob received Alice's CPU room message",
        )

        carol_got = carol.wait_for(MsgType.ROOM_MSG, timeout=1, match={"room": "CPU"})
        self._assert(
            carol_got is None,
            "Carol did NOT receive the CPU room message (not subscribed)",
        )

        # Bob leaves the room
        bob.send({"type": MsgType.LEAVE_ROOM, "room": "CPU"})
        time.sleep(0.3)
        leave_ack = bob.wait_for(MsgType.LEAVE_ROOM)
        self._assert(leave_ack is not None, "Bob left CPU room")

    def _test_private_msg(self, alice, bob, carol):
        print("\n--- Test 4: Private Messaging ---")

        alice.send(make_private_msg("Alice", "Bob", "Hey Bob, private msg!"))
        time.sleep(0.3)

        bob_pm = bob.wait_for(MsgType.PRIVATE_MSG)
        self._assert(
            bob_pm is not None and bob_pm.get("text") == "Hey Bob, private msg!",
            "Bob received private message from Alice",
        )

        carol_pm = carol.wait_for(MsgType.PRIVATE_MSG, timeout=1)
        self._assert(
            carol_pm is None,
            "Carol did NOT receive Alice->Bob private message",
        )

    def _test_status_update(self, alice, bob, carol):
        print("\n--- Test 5: Status Update Broadcast ---")

        metrics = {"cpu": 78.2, "bandwidth_mbps": 42.5, "packet_loss": 0.3}
        alice.send(make_status_update("Alice", metrics))
        time.sleep(0.3)

        bob_status = bob.wait_for(MsgType.STATUS_UPDATE)
        self._assert(
            bob_status is not None and bob_status.get("metrics", {}).get("cpu") == 78.2,
            "Bob received Alice's status update with correct metrics",
        )

        carol_status = carol.wait_for(MsgType.STATUS_UPDATE)
        self._assert(
            carol_status is not None,
            "Carol also received Alice's status update",
        )

    def _test_file_sharing(self, alice, bob, carol):
        print("\n--- Test 6: File Sharing ---")

        # Alice uploads a dummy log file
        dummy_content = b"[LOG] 2026-06-07 CPU spike detected on node-3\n" * 10
        b64_data = base64.b64encode(dummy_content).decode("utf-8")

        alice.send(make_file_share(
            username="Alice",
            filename="alert_log_2026.txt",
            file_data_b64=b64_data,
            file_size=len(dummy_content),
            file_type="text/plain",
        ))
        time.sleep(0.5)

        # Bob should get a file notification
        bob_notif = bob.wait_for(MsgType.FILE_SHARE)
        self._assert(
            bob_notif is not None and bob_notif.get("filename") == "alert_log_2026.txt",
            "Bob received file share notification",
        )

        # Carol should get file list
        carol_list = carol.wait_for(MsgType.FILE_LIST)
        self._assert(
            carol_list is not None and len(carol_list.get("files", [])) > 0,
            "Carol received updated file list",
        )

        # Bob requests the file
        bob.send({"type": MsgType.FILE_REQUEST, "filename": "alert_log_2026.txt"})
        time.sleep(0.3)

        bob_file = bob.wait_for(MsgType.FILE_RESPONSE)
        if bob_file:
            downloaded = base64.b64decode(bob_file.get("file_data", ""))
            self._assert(
                downloaded == dummy_content,
                "Bob downloaded file matches original content",
            )
        else:
            self._assert(False, "Bob received file data")

    def _test_emergency(self, alice, bob, carol):
        print("\n--- Test 7: Emergency Broadcast ---")

        carol.send(make_emergency("Carol", "CRITICAL: Intrusion detected on node-7!"))
        time.sleep(0.3)

        alice_emg = alice.wait_for(MsgType.EMERGENCY)
        self._assert(
            alice_emg is not None and "Intrusion" in alice_emg.get("message", ""),
            "Alice received emergency broadcast",
        )

        bob_emg = bob.wait_for(MsgType.EMERGENCY)
        self._assert(
            bob_emg is not None,
            "Bob received emergency broadcast",
        )

        carol_emg = carol.wait_for(MsgType.EMERGENCY)
        self._assert(
            carol_emg is not None,
            "Carol also received her own emergency (confirmation)",
        )


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated test client for Network Monitoring Server"
    )
    parser.add_argument(
        "--host", default=DEFAULT_HOST,
        help=f"Server address (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"Server port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--ssl", action="store_true",
        help="Connect with TLS/SSL",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    runner = TestRunner(host=args.host, port=args.port, use_ssl=args.ssl)
    success = runner.run_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
