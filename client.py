"""
client.py — Web-Bridge Client Architecture & Test Client
=========================================================
Acts as a local proxy. Serves the stunning Glassmorphic HTML/CSS/JS 
frontend locally via Flask-SocketIO, while connecting to the main
remote Network Monitoring Server via raw TCP sockets.

Also houses the automated integration test suite running via the --test flag.
"""

# Standard threading is used for Python 3.13 compatibility

import os
import base64
import random
import socket
import ssl
import threading
import time
import json
import struct
import sys
import argparse
from datetime import datetime

from flask import Flask, send_from_directory
from flask_socketio import SocketIO

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
    """Build a FILE_SHARE payload."""
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


# ---------------------------------------------------------------------------
# App & State Initialization
# ---------------------------------------------------------------------------

app = Flask(__name__, static_folder="static")
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*", max_decode_size=50 * 1024 * 1024)

from flask import request

class BridgeState:
    def __init__(self, sid):
        self.sid = sid
        self.sock: socket.socket | None = None
        self.connected = False
        self.username = ""
        self.host = ""
        self.port = 0
        self.use_ssl = False
        
        self.stop_event = threading.Event()
        self.receiver_thread: threading.Thread | None = None
        self.metrics_thread: threading.Thread | None = None
        
        # Simulated metrics (RAM and Temperature added)
        self.metrics = {"cpu": 0.0, "bandwidth_mbps": 0.0, "ram": 0.0, "temp": 0.0, "packet_loss": 0.0}
        self.emergency_triggered = False
        
        # Virtual node simulation control
        self.virtual_nodes_running = False
        self.virtual_stop_event: threading.Event | None = None

active_sessions = {}
sessions_lock = threading.Lock()

def get_session_state(sid=None) -> BridgeState | None:
    if sid is None:
        sid = getattr(request, "sid", None)
    if not sid:
        return None
    with sessions_lock:
        return active_sessions.get(sid)

# ---------------------------------------------------------------------------
# Flask Routes (Serve Frontend)
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("static", path)


# ---------------------------------------------------------------------------
# SocketIO Handlers (Browser -> Python Bridge)
# ---------------------------------------------------------------------------

@socketio.on('connect')
def on_browser_connect():
    sid = request.sid
    print(f"[Flask] Browser connected to local Web-Bridge. sid={sid}")
    with sessions_lock:
        active_sessions[sid] = BridgeState(sid)

@socketio.on('disconnect')
def on_browser_disconnect():
    sid = request.sid
    print(f"[Flask] Browser disconnected. sid={sid}")
    disconnect_from_server(sid)

@socketio.on('bridge_connect')
def handle_bridge_connect(data):
    sid = request.sid
    state = get_session_state(sid)
    if not state:
        state = BridgeState(sid)
        with sessions_lock:
            active_sessions[sid] = state

    if state.connected:
        return
        
    state.host = data.get("host", DEFAULT_HOST)
    state.port = int(data.get("port", DEFAULT_PORT))
    state.username = data.get("username", f"User_{random.randint(100,999)}")
    state.use_ssl = data.get("use_ssl", False)
    
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if state.use_ssl:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_verify_locations(SERVER_CERT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
            state.sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
        else:
            state.sock = raw_sock

        state.sock.connect((state.host, state.port))
        
        # Handshake
        hostname = socket.gethostname()
        send_msg(state.sock, make_connect_msg(state.username, hostname, socket.gethostbyname(hostname)))
        
        state.connected = True
        state.emergency_triggered = False
        state.stop_event.clear()
        
        # Start background threads for raw TCP
        state.receiver_thread = threading.Thread(target=receive_loop, args=(state,), daemon=True)
        state.receiver_thread.start()
        state.metrics_thread = threading.Thread(target=metrics_loop, args=(state,), daemon=True)
        state.metrics_thread.start()
        
        socketio.emit('bridge_connected', {
            "username": state.username,
            "host": state.host,
            "port": state.port
        }, room=sid)
        
        # Request initial file list
        send_msg_safe(state, {"type": MsgType.FILE_LIST})
        
    except Exception as e:
        print(f"[Error] Failed to connect: {e}")
        socketio.emit('event_log', {"text": f"Connection failed: {e}"}, room=sid)
        disconnect_from_server(sid)

@socketio.on('bridge_disconnect')
def handle_bridge_disconnect():
    disconnect_from_server(request.sid)

@socketio.on('room_toggle')
def handle_room_toggle(data):
    state = get_session_state()
    if not state:
        return
    room = data.get("room")
    action = data.get("action")
    if action == "join":
        send_msg_safe(state, {"type": MsgType.JOIN_ROOM, "room": room})
    else:
        send_msg_safe(state, {"type": MsgType.LEAVE_ROOM, "room": room})

@socketio.on('send_room')
def handle_send_room(data):
    state = get_session_state()
    if not state:
        return
    send_msg_safe(state, make_room_msg(state.username, data.get("room"), data.get("text")))

@socketio.on('send_private')
def handle_send_private(data):
    state = get_session_state()
    if not state:
        return
    send_msg_safe(state, make_private_msg(state.username, data.get("recipient"), data.get("text")))

@socketio.on('upload_file')
def handle_upload_file(data):
    state = get_session_state()
    if not state:
        return
    send_msg_safe(state, make_file_share(
        state.username,
        data.get("filename"),
        data.get("file_data"),
        data.get("file_size"),
        data.get("file_type")
    ))

@socketio.on('download_file')
def handle_download_file(data):
    state = get_session_state()
    if not state:
        return
    send_msg_safe(state, {"type": MsgType.FILE_REQUEST, "filename": data.get("filename")})

@socketio.on('trigger_emergency')
def handle_trigger_emergency(data):
    state = get_session_state()
    if not state:
        return
    send_msg_safe(state, make_emergency(state.username, data.get("message")))


# ---------------------------------------------------------------------------
# Raw TCP Handlers & Background Threads (Python Bridge -> Main Server)
# ---------------------------------------------------------------------------

def disconnect_from_server(sid, reason="User initiated"):
    state = None
    with sessions_lock:
        state = active_sessions.pop(sid, None)
        
    if state:
        state.stop_event.set()
        if state.virtual_stop_event:
            state.virtual_stop_event.set()
        state.virtual_nodes_running = False
        if state.sock:
            try:
                send_msg(state.sock, {"type": MsgType.DISCONNECT})
                state.sock.close()
            except Exception:
                pass
        state.sock = None
        state.connected = False
        socketio.emit('bridge_disconnected', {"reason": reason}, room=sid)

def send_msg_safe(state: BridgeState, payload: dict):
    if not state or not state.connected or not state.sock:
        return
    try:
        send_msg(state.sock, payload)
    except Exception as e:
        print(f"[TCP Send Error] {e}")
        disconnect_from_server(state.sid, str(e))

def receive_loop(state: BridgeState):
    while not state.stop_event.is_set():
        try:
            msg = recv_msg(state.sock)
            if msg is None:
                break
            route_tcp_to_ws(msg, state)
        except Exception as e:
            if not state.stop_event.is_set():
                print(f"[TCP Recv Error] {e}")
                socketio.emit('event_log', {"text": f"Connection lost: {e}"}, room=state.sid)
            break
            
    if not state.stop_event.is_set():
        disconnect_from_server(state.sid, "Connection dropped")

def metrics_loop(state: BridgeState):
    # Pure randomized simulation data as requested (no need to use psutil or shell commands)
    cpu_usage = 35.0
    bandwidth = 180.0
    ram_usage = 45.0
    temperature = 50.0

    while not state.stop_event.is_set():
        # Random walks to simulate metrics naturally
        cpu_usage = max(0.0, min(100.0, cpu_usage + random.uniform(-10.0, 10.0)))
        bandwidth = max(0.0, min(1000.0, bandwidth + random.uniform(-60.0, 60.0)))
        ram_usage = max(0.0, min(100.0, ram_usage + random.uniform(-5.0, 5.0)))
        temperature = max(20.0, min(110.0, temperature + random.uniform(-4.0, 4.0)))
        
        state.metrics["cpu"] = float(cpu_usage)
        state.metrics["bandwidth_mbps"] = float(bandwidth)
        state.metrics["ram"] = float(ram_usage)
        state.metrics["temp"] = float(temperature)
        state.metrics["packet_loss"] = float(random.choice([0.0, 0.0, 0.0, 1.0, 2.0]))
        
        if state.connected:
            send_msg_safe(state, make_status_update(state.username, state.metrics))
            # Push metrics to local dashboard
            socketio.emit('metrics_update', state.metrics, room=state.sid)
            
            # Alerts verification (CPU, Bandwidth, RAM, Temperature)
            cpu_breached = state.metrics["cpu"] > 90.0
            bw_breached = state.metrics["bandwidth_mbps"] > 900.0
            ram_breached = state.metrics["ram"] > 90.0
            temp_breached = state.metrics["temp"] > 80.0
            
            if (cpu_breached or bw_breached or ram_breached or temp_breached) and not state.emergency_triggered:
                state.emergency_triggered = True
                alert_text = "CRITICAL METRIC EXCEEDED: "
                alerts = []
                if cpu_breached:
                    alerts.append(f"CPU at {state.metrics['cpu']:.1f}%")
                if bw_breached:
                    alerts.append(f"Bandwidth at {state.metrics['bandwidth_mbps']:.1f} Mbps")
                if ram_breached:
                    alerts.append(f"RAM at {state.metrics['ram']:.1f}%")
                if temp_breached:
                    alerts.append(f"Temperature at {state.metrics['temp']:.1f}°C")
                alert_text += ", ".join(alerts)
                
                send_msg_safe(state, make_emergency(state.username, alert_text))
            elif not (cpu_breached or bw_breached or ram_breached or temp_breached) and state.emergency_triggered:
                state.emergency_triggered = False
            
        time.sleep(2.0)

# ---------------------------------------------------------------------------
# Dynamic Concurrency presentation simulator
# ---------------------------------------------------------------------------

def run_virtual_node(username: str, host: str, port: int, use_ssl: bool, stop_event: threading.Event):
    sock = None
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if use_ssl:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_verify_locations(SERVER_CERT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
            sock = ctx.wrap_socket(raw, server_hostname="localhost")
        else:
            sock = raw
            
        sock.connect((host, port))
        
        # CONNECT handshake
        send_msg(sock, make_connect_msg(username, f"virtual-{username}", host))
        
        # CONNECT_ACK
        ack = recv_msg(sock)
        if not ack or ack.get("type") != MsgType.CONNECT_ACK:
            return
            
        # Join random alert room
        send_msg(sock, {"type": MsgType.JOIN_ROOM, "room": random.choice(["CPU", "Bandwidth", "Security"])})
        
        # Start virtual receiver thread
        def recv_loop_virtual():
            while not stop_event.is_set():
                try:
                    m = recv_msg(sock)
                    if m is None:
                        break
                except Exception:
                    break
        
        threading.Thread(target=recv_loop_virtual, daemon=True).start()
        
        # Status loop
        metrics = {"cpu": 30.0, "bandwidth_mbps": 100.0, "ram": 45.0, "temp": 50.0, "packet_loss": 0.0}
        while not stop_event.is_set():
            metrics["cpu"] = min(100.0, max(0.0, metrics["cpu"] + random.uniform(-15, 15)))
            metrics["bandwidth_mbps"] = min(1000.0, max(0.0, metrics["bandwidth_mbps"] + random.uniform(-60, 60)))
            metrics["ram"] = min(100.0, max(0.0, metrics["ram"] + random.uniform(-5, 5)))
            metrics["temp"] = min(100.0, max(0.0, metrics["temp"] + random.uniform(-4, 4)))
            send_msg(sock, make_status_update(username, metrics))
            time.sleep(2.0)
            
    except Exception as e:
        print(f"[Virtual Node {username} Error] {e}")
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

@socketio.on('simulate_concurrency')
def handle_simulate_concurrency(data):
    state = get_session_state()
    if not state:
        return
    action = data.get("action", "start")
    
    if action == "start":
        if state.virtual_nodes_running:
            return
        if not state.connected:
            socketio.emit('event_log', {"text": "Cannot start simulation while disconnected from server."}, room=state.sid)
            return
            
        state.virtual_nodes_running = True
        state.virtual_stop_event = threading.Event()
        
        # Spawns Alice, Bob, Carol background clients
        names = [f"Alice_{state.username}", f"Bob_{state.username}", f"Carol_{state.username}"]
        for name in names:
            t = threading.Thread(
                target=run_virtual_node,
                args=(name, state.host, state.port, state.use_ssl, state.virtual_stop_event),
                daemon=True
            )
            t.start()
        socketio.emit('event_log', {"text": "Simulation started: Spawning virtual clients (Alice, Bob, Carol)..."}, room=state.sid)
        socketio.emit('simulation_state', {"running": True}, room=state.sid)
    else:
        if not state.virtual_nodes_running:
            return
        state.virtual_nodes_running = False
        if state.virtual_stop_event:
            state.virtual_stop_event.set()
        socketio.emit('event_log', {"text": "Simulation stopped: Disconnecting virtual clients."}, room=state.sid)
        socketio.emit('simulation_state', {"running": False}, room=state.sid)

def route_tcp_to_ws(msg: dict, state: BridgeState):
    """Takes an incoming TCP packet from the main server and emits a WS event."""
    mtype = msg.get("type")
    sid = state.sid
    
    if mtype == MsgType.CONNECT_ACK:
        socketio.emit('event_log', {"text": f"Server: {msg.get('message')}"}, room=sid)
        
    elif mtype == MsgType.CLIENT_LIST:
        socketio.emit('client_list', msg, room=sid)
        
    elif mtype == MsgType.STATUS_UPDATE:
        username = msg.get("username")
        m = msg.get("metrics", {})
        socketio.emit('node_metrics_update', {"username": username, "metrics": m}, room=sid)
        if m.get("cpu", 0) > 95:
            socketio.emit('event_log', {"text": f"ALERT: Node '{username}' CPU critically high!"}, room=sid)
            
    elif mtype in (MsgType.JOIN_ROOM, MsgType.LEAVE_ROOM):
        socketio.emit('event_log', {"text": msg.get("message")}, room=sid)
        
    elif mtype == MsgType.ROOM_MSG:
        socketio.emit('room_msg', msg, room=sid)
        
    elif mtype == MsgType.PRIVATE_MSG:
        socketio.emit('private_msg', msg, room=sid)
        
    elif mtype == MsgType.FILE_LIST:
        socketio.emit('file_list', msg, room=sid)
        
    elif mtype == MsgType.FILE_SHARE:
        fn = msg.get("filename")
        socketio.emit('event_log', {"text": f"{msg.get('username')} shared a new file: {fn}"}, room=sid)
        send_msg_safe(state, {"type": MsgType.FILE_LIST})
        
    elif mtype == MsgType.FILE_RESPONSE:
        socketio.emit('file_receive', msg, room=sid)
        
    elif mtype == MsgType.EMERGENCY:
        socketio.emit('emergency', msg, room=sid)
        
    elif mtype == MsgType.ERROR:
        socketio.emit('event_log', {"text": f"SERVER ERROR: {msg.get('detail')}"}, room=sid)


# ---------------------------------------------------------------------------
# Section 5: Automated CLI Test Suite (formerly test_client.py)
# ---------------------------------------------------------------------------

class VirtualClient:
    """Lightweight test client that connects and receives messages."""
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

    def connect(self):
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

        send_msg(self.sock, make_connect_msg(
            username=self.username,
            hostname=f"host-{self.username}",
            ip=self.host,
        ))

        self._stop_event.clear()
        self._receiver_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self._receiver_thread.start()

        ack = self.wait_for(MsgType.CONNECT_ACK, timeout=5)
        if ack:
            self.connected = True
            print(f"[{self.username}] Connected: {ack.get('message')}")
        else:
            print(f"[{self.username}] Did not receive CONNECT_ACK!")

    def disconnect(self):
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
        print(f"[{self.username}] Disconnected.")

    def _receive_loop(self):
        while not self._stop_event.is_set():
            try:
                msg = recv_msg(self.sock)
                if msg is None:
                    break
                with self.inbox_lock:
                    self.inbox.append(msg)
            except ConnectionError:
                break
            except Exception:
                break

    def send(self, payload: dict):
        send_msg(self.sock, payload)

    def wait_for(self, msg_type: str, timeout: float = 3.0, match: dict = None) -> dict | None:
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

class TestRunner:
    """Runs all automated TCP backend integration tests."""
    def __init__(self, host: str, port: int, use_ssl: bool):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.passed = 0
        self.failed = 0

    def _assert(self, condition: bool, label: str):
        if condition:
            self.passed += 1
            print(f"  [PASS] {label}")
        else:
            self.failed += 1
            print(f"  [FAIL] {label}")

    def run_all(self):
        alice = VirtualClient(self.host, self.port, "Alice", self.use_ssl)
        bob   = VirtualClient(self.host, self.port, "Bob",   self.use_ssl)
        carol = VirtualClient(self.host, self.port, "Carol", self.use_ssl)

        try:
            # --- 1. Multi-client connection ---
            print("\n--- Test 1: Multi-Client Connection ---")
            alice.connect()
            self._assert(alice.connected, "Alice connected")
            bob.connect()
            self._assert(bob.connected, "Bob connected")
            carol.connect()
            self._assert(carol.connected, "Carol connected")

            # --- 2. Client discovery ---
            print("\n--- Test 2: Client Discovery ---")
            time.sleep(0.5)
            lists_a = alice.drain(MsgType.CLIENT_LIST)
            if lists_a:
                latest = lists_a[-1]
                names = [c["username"] for c in latest.get("clients", [])]
                self._assert("Bob" in names, "Alice sees Bob in client list")
                self._assert("Carol" in names, "Alice sees Carol in client list")
            else:
                self._assert(False, "Alice received a CLIENT_LIST")

            # --- 3. Room join & messaging ---
            print("\n--- Test 3: Alert Rooms ---")
            alice.send({"type": MsgType.JOIN_ROOM, "room": "CPU"})
            bob.send({"type": MsgType.JOIN_ROOM, "room": "CPU"})
            time.sleep(0.3)

            ack_a = alice.wait_for(MsgType.JOIN_ROOM, match={"room": "CPU"})
            self._assert(ack_a is not None, "Alice joined CPU room")
            ack_b = bob.wait_for(MsgType.JOIN_ROOM, match={"room": "CPU"})
            self._assert(ack_b is not None, "Bob joined CPU room")

            alice.drain(MsgType.ROOM_MSG)
            bob.drain(MsgType.ROOM_MSG)
            carol.drain(MsgType.ROOM_MSG)

            alice.send(make_room_msg("Alice", "CPU", "CPU usage is at 95%!"))
            time.sleep(0.3)

            bob_got = bob.wait_for(MsgType.ROOM_MSG, match={"room": "CPU"})
            self._assert(
                bob_got is not None and bob_got.get("username") == "Alice",
                "Bob received Alice's CPU room message",
            )

            carol_got = carol.wait_for(MsgType.ROOM_MSG, timeout=1, match={"room": "CPU"})
            self._assert(carol_got is None, "Carol did NOT receive CPU room message")

            bob.send({"type": MsgType.LEAVE_ROOM, "room": "CPU"})
            time.sleep(0.3)
            leave_ack = bob.wait_for(MsgType.LEAVE_ROOM)
            self._assert(leave_ack is not None, "Bob left CPU room")

            # --- 4. Private messaging ---
            print("\n--- Test 4: Private Messaging ---")
            alice.send(make_private_msg("Alice", "Bob", "Hey Bob, private msg!"))
            time.sleep(0.3)

            bob_pm = bob.wait_for(MsgType.PRIVATE_MSG)
            self._assert(
                bob_pm is not None and bob_pm.get("text") == "Hey Bob, private msg!",
                "Bob received private message from Alice",
            )
            carol_pm = carol.wait_for(MsgType.PRIVATE_MSG, timeout=1)
            self._assert(carol_pm is None, "Carol did NOT receive direct message")

            # --- 5. Status update broadcast ---
            print("\n--- Test 5: Status Update Broadcast ---")
            metrics = {
                "cpu": 78.2,
                "bandwidth_mbps": 42.5,
                "ram": 60.0,
                "temp": 55.0,
                "packet_loss": 0.3
            }
            alice.send(make_status_update("Alice", metrics))
            time.sleep(0.3)

            bob_status = bob.wait_for(MsgType.STATUS_UPDATE)
            self._assert(
                bob_status is not None and bob_status.get("metrics", {}).get("cpu") == 78.2,
                "Bob received Alice's status update with correct metrics",
            )
            carol_status = carol.wait_for(MsgType.STATUS_UPDATE)
            self._assert(carol_status is not None, "Carol received Alice's status update")

            # --- 6. File sharing ---
            print("\n--- Test 6: File Sharing ---")
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

            bob_notif = bob.wait_for(MsgType.FILE_SHARE)
            self._assert(
                bob_notif is not None and bob_notif.get("filename") == "alert_log_2026.txt",
                "Bob received file share notification",
            )

            carol_list = carol.wait_for(MsgType.FILE_LIST)
            self._assert(
                carol_list is not None and len(carol_list.get("files", [])) > 0,
                "Carol received updated file list",
            )

            bob.send({"type": MsgType.FILE_REQUEST, "filename": "alert_log_2026.txt"})
            time.sleep(0.3)

            bob_file = bob.wait_for(MsgType.FILE_RESPONSE)
            if bob_file:
                downloaded = base64.b64decode(bob_file.get("file_data", ""))
                self._assert(downloaded == dummy_content, "Bob downloaded file matches original")
            else:
                self._assert(False, "Bob received file data")

            # --- 7. Emergency broadcast ---
            print("\n--- Test 7: Emergency Broadcast ---")
            carol.send(make_emergency("Carol", "CRITICAL: Intrusion detected on node-7!"))
            time.sleep(0.3)

            alice_emg = alice.wait_for(MsgType.EMERGENCY)
            self._assert(
                alice_emg is not None and "Intrusion" in alice_emg.get("message", ""),
                "Alice received emergency broadcast",
            )
            bob_emg = bob.wait_for(MsgType.EMERGENCY)
            self._assert(bob_emg is not None, "Bob received emergency broadcast")
            carol_emg = carol.wait_for(MsgType.EMERGENCY)
            self._assert(carol_emg is not None, "Carol received emergency confirmation")

        finally:
            alice.disconnect()
            bob.disconnect()
            carol.disconnect()

        total = self.passed + self.failed
        print("\n" + "=" * 60)
        print(f"  Results: {self.passed}/{total} passed, {self.failed} failed")
        print("=" * 60 + "\n")

        return self.failed == 0


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Network Monitoring Client (Web-Bridge) & Automated Test Client"
    )
    parser.add_argument(
        "--test", action="store_true",
        help="Run the automated backend integration test suite",
    )
    parser.add_argument(
        "--host", default=DEFAULT_HOST,
        help=f"Server address (for test suite) (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help=f"Server port (for test suite) (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--ssl", action="store_true",
        help="Connect to test server with TLS/SSL",
    )
    args = parser.parse_args()

    if args.test:
        print("=" * 60)
        print("  Starting Automated Integration Tests")
        print("=" * 60)
        runner = TestRunner(host=args.host, port=args.port, use_ssl=args.ssl)
        success = runner.run_all()
        sys.exit(0 if success else 1)
    else:
        print("=" * 55)
        print("  Network Nexus Client (Web-Bridge)")
        print("=======================================================")
        print("  Available locally at: http://localhost:8080")
        print("  Available on your LAN at: http://<your-ip>:8080")
        print("=======================================================")
        # Bind to 0.0.0.0 to enable access from other LAN devices
        socketio.run(app, host="0.0.0.0", port=8080, debug=False, allow_unsafe_werkzeug=True)
