"""
client.py — Web-Bridge Client Architecture
==========================================
Acts as a local proxy. Serves the stunning Glassmorphic HTML/CSS/JS 
frontend locally via Flask-SocketIO, while connecting to the main
remote Network Monitoring Server via raw TCP sockets.
"""

import eventlet
# Monkey-patch is required for eventlet to handle threading and sockets properly with SocketIO
eventlet.monkey_patch()

import os
import random
import socket
import ssl
import threading
import time
from datetime import datetime

from flask import Flask, send_from_directory
from flask_socketio import SocketIO

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
)

# ---------------------------------------------------------------------------
# App & State Initialization
# ---------------------------------------------------------------------------

app = Flask(__name__, static_folder="static")
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

class BridgeState:
    def __init__(self):
        self.sock: socket.socket | None = None
        self.connected = False
        self.username = ""
        self.host = ""
        self.port = 0
        self.use_ssl = False
        
        self.stop_event = threading.Event()
        self.receiver_thread: threading.Thread | None = None
        self.metrics_thread: threading.Thread | None = None
        
        # Simulated metrics
        self.metrics = {"cpu": 0.0, "bandwidth_mbps": 0.0, "packet_loss": 0.0}

state = BridgeState()

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
    print("[Flask] Browser connected to local Web-Bridge.")

@socketio.on('disconnect')
def on_browser_disconnect():
    print("[Flask] Browser disconnected. Shutting down TCP link to server.")
    disconnect_from_server()

@socketio.on('bridge_connect')
def handle_bridge_connect(data):
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
        state.stop_event.clear()
        
        # Start background threads for raw TCP
        state.receiver_thread = eventlet.spawn(receive_loop)
        state.metrics_thread = eventlet.spawn(metrics_loop)
        
        socketio.emit('bridge_connected', {
            "username": state.username,
            "host": state.host,
            "port": state.port
        })
        
        # Request initial file list
        send_msg_safe({"type": MsgType.FILE_LIST})
        
    except Exception as e:
        print(f"[Error] Failed to connect: {e}")
        socketio.emit('event_log', {"text": f"Connection failed: {e}"})
        disconnect_from_server()

@socketio.on('bridge_disconnect')
def handle_bridge_disconnect():
    disconnect_from_server()

@socketio.on('room_toggle')
def handle_room_toggle(data):
    room = data.get("room")
    action = data.get("action")
    if action == "join":
        send_msg_safe({"type": MsgType.JOIN_ROOM, "room": room})
    else:
        send_msg_safe({"type": MsgType.LEAVE_ROOM, "room": room})

@socketio.on('send_room')
def handle_send_room(data):
    send_msg_safe(make_room_msg(state.username, data.get("room"), data.get("text")))

@socketio.on('send_private')
def handle_send_private(data):
    send_msg_safe(make_private_msg(state.username, data.get("recipient"), data.get("text")))

@socketio.on('upload_file')
def handle_upload_file(data):
    send_msg_safe(make_file_share(
        state.username,
        data.get("filename"),
        data.get("file_data"),
        data.get("file_size"),
        data.get("file_type")
    ))

@socketio.on('download_file')
def handle_download_file(data):
    send_msg_safe({"type": MsgType.FILE_REQUEST, "filename": data.get("filename")})

@socketio.on('trigger_emergency')
def handle_trigger_emergency(data):
    send_msg_safe(make_emergency(state.username, data.get("message")))


# ---------------------------------------------------------------------------
# Raw TCP Handlers & Background Threads (Python Bridge -> Main Server)
# ---------------------------------------------------------------------------

def disconnect_from_server(reason="User initiated"):
    state.stop_event.set()
    if state.sock:
        try:
            send_msg(state.sock, {"type": MsgType.DISCONNECT})
            state.sock.close()
        except Exception:
            pass
    state.sock = None
    state.connected = False
    socketio.emit('bridge_disconnected', {"reason": reason})

def send_msg_safe(payload: dict):
    if not state.connected or not state.sock:
        return
    try:
        send_msg(state.sock, payload)
    except Exception as e:
        print(f"[TCP Send Error] {e}")
        disconnect_from_server(str(e))

def receive_loop():
    while not state.stop_event.is_set():
        try:
            msg = recv_msg(state.sock)
            if msg is None:
                break
            route_tcp_to_ws(msg)
        except Exception as e:
            if not state.stop_event.is_set():
                print(f"[TCP Recv Error] {e}")
                socketio.emit('event_log', {"text": f"Connection lost: {e}"})
            break
            
    if not state.stop_event.is_set():
        disconnect_from_server("Connection dropped")

def metrics_loop():
    while not state.stop_event.is_set():
        # Random walk for simulated metrics
        state.metrics["cpu"] = min(100.0, max(0.0, state.metrics["cpu"] + random.uniform(-10, 10)))
        state.metrics["bandwidth_mbps"] = min(1000.0, max(0.0, state.metrics["bandwidth_mbps"] + random.uniform(-50, 50)))
        
        if state.connected:
            send_msg_safe(make_status_update(state.username, state.metrics))
            # Push strictly our own metrics to the web UI to draw the charts
            socketio.emit('metrics_update', state.metrics)
            
        eventlet.sleep(2.0)

def route_tcp_to_ws(msg: dict):
    """Takes an incoming TCP packet from the main server and emits a WS event."""
    mtype = msg.get("type")
    
    if mtype == MsgType.CONNECT_ACK:
        socketio.emit('event_log', {"text": f"Server: {msg.get('message')}"})
        
    elif mtype == MsgType.CLIENT_LIST:
        socketio.emit('client_list', msg)
        
    elif mtype == MsgType.STATUS_UPDATE:
        # Received metrics from another node. We could emit this to show in UI.
        m = msg.get("metrics", {})
        if m.get("cpu", 0) > 95:
            socketio.emit('event_log', {"text": f"ALERT: Node '{msg.get('username')}' CPU critically high!"})
            
    elif mtype in (MsgType.JOIN_ROOM, MsgType.LEAVE_ROOM):
        socketio.emit('event_log', {"text": msg.get("message")})
        
    elif mtype == MsgType.ROOM_MSG:
        socketio.emit('room_msg', msg)
        
    elif mtype == MsgType.PRIVATE_MSG:
        socketio.emit('private_msg', msg)
        
    elif mtype == MsgType.FILE_LIST:
        socketio.emit('file_list', msg)
        
    elif mtype == MsgType.FILE_SHARE:
        fn = msg.get("filename")
        socketio.emit('event_log', {"text": f"{msg.get('username')} shared a new file: {fn}"})
        send_msg_safe({"type": MsgType.FILE_LIST})
        
    elif mtype == MsgType.FILE_RESPONSE:
        socketio.emit('file_receive', msg)
        
    elif mtype == MsgType.EMERGENCY:
        socketio.emit('emergency', msg)
        
    elif mtype == MsgType.ERROR:
        socketio.emit('event_log', {"text": f"SERVER ERROR: {msg.get('detail')}"})

# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 55)
    print("  Network Monitoring Client (Web-Bridge)")
    print("=======================================================")
    print("  Open your browser to: http://localhost:8080")
    print("=======================================================")
    # Using eventlet directly via socketio.run is recommended
    socketio.run(app, host="127.0.0.1", port=8080, debug=False)
