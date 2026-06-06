"""
client.py — Collaborative Network Monitoring Client
===================================================
A modern, dark-themed Tkinter GUI application that connects to the
Network Monitoring Server. Features include:
  • Simulated real-time metrics (CPU, Bandwidth, Packet Loss)
  • Active node discovery
  • Group rooms and private messaging
  • File sharing (logs, screenshots, videos)
  • Global emergency alerts with audio (via winsound)
"""

import base64
import os
import random
import socket
import ssl
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

# Attempt to load winsound for emergency audio alerts (Windows only)
try:
    import winsound
    HAS_WINSOUND = True
except ImportError:
    HAS_WINSOUND = False

from utils import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    SERVER_CERT,
    ALERT_ROOMS,
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
# Theme Colors (Catppuccin Mocha inspired)
# ---------------------------------------------------------------------------
BG_BASE = "#1e1e2e"
BG_SURFACE = "#313244"
FG_TEXT = "#cdd6f4"
ACCENT_BLUE = "#89b4fa"
ACCENT_RED = "#f38ba8"
ACCENT_GREEN = "#a6e3a1"
ACCENT_YELLOW = "#f9e2af"

def setup_theme(root: tk.Tk):
    """Apply a modern dark theme to standard Tkinter/ttk widgets."""
    style = ttk.Style(root)
    style.theme_use('clam')
    
    # Configure root window background
    root.configure(bg=BG_BASE)
    
    # Configure generic styles
    style.configure("TFrame", background=BG_BASE)
    style.configure("Surface.TFrame", background=BG_SURFACE)
    
    style.configure("TLabel", background=BG_BASE, foreground=FG_TEXT, font=("Segoe UI", 10))
    style.configure("Surface.TLabel", background=BG_SURFACE, foreground=FG_TEXT, font=("Segoe UI", 10))
    style.configure("Header.TLabel", background=BG_BASE, foreground=ACCENT_BLUE, font=("Segoe UI", 14, "bold"))
    
    style.configure("TButton",
                    background=BG_SURFACE,
                    foreground=FG_TEXT,
                    borderwidth=0,
                    focusthickness=3,
                    focuscolor=ACCENT_BLUE,
                    font=("Segoe UI", 10))
    style.map("TButton",
              background=[("active", ACCENT_BLUE)],
              foreground=[("active", BG_BASE)])
              
    style.configure("Danger.TButton",
                    background=ACCENT_RED,
                    foreground=BG_BASE,
                    font=("Segoe UI", 10, "bold"))
    style.map("Danger.TButton", background=[("active", "#ffb3c6")])

    style.configure("TEntry", fieldbackground=BG_SURFACE, foreground=FG_TEXT, borderwidth=0)
    style.configure("TCheckbutton", background=BG_BASE, foreground=FG_TEXT)
    style.map("TCheckbutton", background=[("active", BG_BASE)])
    
    style.configure("TNotebook", background=BG_BASE, borderwidth=0)
    style.configure("TNotebook.Tab", background=BG_SURFACE, foreground=FG_TEXT, padding=[10, 5])
    style.map("TNotebook.Tab", background=[("selected", ACCENT_BLUE)], foreground=[("selected", BG_BASE)])

# ---------------------------------------------------------------------------
# Client GUI Application
# ---------------------------------------------------------------------------
class NetworkMonitorClient:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Collaborative Network Monitoring Dashboard")
        self.root.geometry("1000x700")
        setup_theme(self.root)
        
        # State
        self.sock: socket.socket | None = None
        self.connected = False
        self.username = ""
        self.active_nodes = []
        self.shared_files = []
        self.subscribed_rooms = set()
        
        # Threads
        self.receiver_thread: threading.Thread | None = None
        self.metrics_thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        
        # Metrics Data
        self.current_metrics = {"cpu": 0.0, "bandwidth_mbps": 0.0, "packet_loss": 0.0}

        self._build_ui()
        
    # =======================================================================
    # UI Building
    # =======================================================================
    def _build_ui(self):
        # --- Top Panel: Connection & Status ---
        conn_frame = ttk.Frame(self.root, padding=10)
        conn_frame.pack(side=tk.TOP, fill=tk.X)
        
        ttk.Label(conn_frame, text="Server IP:").pack(side=tk.LEFT, padx=(0, 5))
        self.entry_ip = ttk.Entry(conn_frame, width=15)
        self.entry_ip.insert(0, DEFAULT_HOST)
        self.entry_ip.pack(side=tk.LEFT, padx=(0, 15))
        
        ttk.Label(conn_frame, text="Port:").pack(side=tk.LEFT, padx=(0, 5))
        self.entry_port = ttk.Entry(conn_frame, width=6)
        self.entry_port.insert(0, str(DEFAULT_PORT))
        self.entry_port.pack(side=tk.LEFT, padx=(0, 15))
        
        ttk.Label(conn_frame, text="Username:").pack(side=tk.LEFT, padx=(0, 5))
        self.entry_user = ttk.Entry(conn_frame, width=15)
        self.entry_user.insert(0, f"User_{random.randint(100,999)}")
        self.entry_user.pack(side=tk.LEFT, padx=(0, 15))
        
        self.var_ssl = tk.BooleanVar(value=False)
        ttk.Checkbutton(conn_frame, text="Use TLS/SSL", variable=self.var_ssl).pack(side=tk.LEFT, padx=(0, 15))
        
        self.btn_connect = ttk.Button(conn_frame, text="Connect", command=self.toggle_connection)
        self.btn_connect.pack(side=tk.LEFT, padx=(0, 15))
        
        self.lbl_status = ttk.Label(conn_frame, text="Disconnected", foreground=ACCENT_RED, font=("Segoe UI", 10, "bold"))
        self.lbl_status.pack(side=tk.RIGHT)
        
        # --- Emergency Banner ---
        self.frame_emergency = tk.Frame(self.root, bg=ACCENT_RED, height=40)
        self.lbl_emergency = tk.Label(self.frame_emergency, text="EMERGENCY ALERT", bg=ACCENT_RED, fg=BG_BASE, font=("Segoe UI", 12, "bold"))
        self.lbl_emergency.pack(expand=True)
        # Not packed initially
        
        # --- Main Notebook ---
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        self._build_dashboard_tab()
        self._build_rooms_tab()
        self._build_private_tab()
        self._build_files_tab()

    def _build_dashboard_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Dashboard")
        
        # Left side: Metrics Simulator
        left_frame = ttk.Frame(tab)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        ttk.Label(left_frame, text="My Simulated Metrics", style="Header.TLabel").pack(anchor=tk.W, pady=(0, 10))
        
        self.lbl_cpu = ttk.Label(left_frame, text="CPU: 0%", font=("Segoe UI", 16))
        self.lbl_cpu.pack(anchor=tk.W, pady=5)
        self.progress_cpu = ttk.Progressbar(left_frame, length=300, mode='determinate')
        self.progress_cpu.pack(anchor=tk.W, pady=(0, 20))
        
        self.lbl_bw = ttk.Label(left_frame, text="Bandwidth: 0 Mbps", font=("Segoe UI", 16))
        self.lbl_bw.pack(anchor=tk.W, pady=5)
        self.progress_bw = ttk.Progressbar(left_frame, length=300, mode='determinate', maximum=1000)
        self.progress_bw.pack(anchor=tk.W, pady=(0, 20))
        
        ttk.Label(left_frame, text="Network Event Logs", style="Header.TLabel").pack(anchor=tk.W, pady=(10, 5))
        self.text_events = tk.Text(left_frame, bg=BG_SURFACE, fg=FG_TEXT, height=10, relief=tk.FLAT, borderwidth=5)
        self.text_events.pack(fill=tk.BOTH, expand=True)
        self.text_events.insert(tk.END, "Event logs will appear here...\n")
        self.text_events.config(state=tk.DISABLED)
        
        # Right side: Active Nodes & Actions
        right_frame = ttk.Frame(tab, width=250)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        ttk.Label(right_frame, text="Active Nodes", style="Header.TLabel").pack(anchor=tk.W, pady=(0, 10))
        self.listbox_nodes = tk.Listbox(right_frame, bg=BG_SURFACE, fg=FG_TEXT, relief=tk.FLAT, borderwidth=5)
        self.listbox_nodes.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        ttk.Button(right_frame, text="Trigger Global Emergency!", style="Danger.TButton", 
                   command=self.trigger_emergency).pack(fill=tk.X, pady=10)

    def _build_rooms_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Group Rooms")
        
        # Room selector
        top_frame = ttk.Frame(tab)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(top_frame, text="Available Alert Rooms:").pack(side=tk.LEFT, padx=(0, 10))
        
        self.room_vars = {}
        for room in ALERT_ROOMS:
            var = tk.BooleanVar(value=False)
            self.room_vars[room] = var
            cb = ttk.Checkbutton(top_frame, text=room, variable=var, 
                                 command=lambda r=room, v=var: self.toggle_room_subscription(r, v.get()))
            cb.pack(side=tk.LEFT, padx=5)
            
        # Chat area
        self.text_rooms = tk.Text(tab, bg=BG_SURFACE, fg=FG_TEXT, relief=tk.FLAT, borderwidth=5)
        self.text_rooms.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.text_rooms.config(state=tk.DISABLED)
        
        # Send area
        btm_frame = ttk.Frame(tab)
        btm_frame.pack(fill=tk.X)
        self.combo_rooms = ttk.Combobox(btm_frame, values=ALERT_ROOMS, state="readonly", width=15)
        self.combo_rooms.set("CPU")
        self.combo_rooms.pack(side=tk.LEFT, padx=(0, 10))
        
        self.entry_room_msg = ttk.Entry(btm_frame)
        self.entry_room_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.entry_room_msg.bind("<Return>", lambda e: self.send_room_msg())
        
        ttk.Button(btm_frame, text="Send", command=self.send_room_msg).pack(side=tk.LEFT)

    def _build_private_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Private Chat")
        
        top_frame = ttk.Frame(tab)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(top_frame, text="Select Node:").pack(side=tk.LEFT, padx=(0, 10))
        
        self.combo_private = ttk.Combobox(top_frame, state="readonly", width=30)
        self.combo_private.pack(side=tk.LEFT)
        
        self.text_private = tk.Text(tab, bg=BG_SURFACE, fg=FG_TEXT, relief=tk.FLAT, borderwidth=5)
        self.text_private.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.text_private.config(state=tk.DISABLED)
        
        btm_frame = ttk.Frame(tab)
        btm_frame.pack(fill=tk.X)
        self.entry_private_msg = ttk.Entry(btm_frame)
        self.entry_private_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.entry_private_msg.bind("<Return>", lambda e: self.send_private_msg())
        ttk.Button(btm_frame, text="Send PM", command=self.send_private_msg).pack(side=tk.LEFT)

    def _build_files_tab(self):
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="File Sharing")
        
        top_frame = ttk.Frame(tab)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(top_frame, text="Upload File...", command=self.upload_file).pack(side=tk.LEFT)
        
        self.listbox_files = tk.Listbox(tab, bg=BG_SURFACE, fg=FG_TEXT, relief=tk.FLAT, borderwidth=5)
        self.listbox_files.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        ttk.Button(tab, text="Download Selected", command=self.download_file).pack(anchor=tk.E)

    # =======================================================================
    # UI Helpers
    # =======================================================================
    def _log_event(self, text: str):
        """Append to the main dashboard event log."""
        self.text_events.config(state=tk.NORMAL)
        self.text_events.insert(tk.END, f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n")
        self.text_events.see(tk.END)
        self.text_events.config(state=tk.DISABLED)

    def _log_room(self, room: str, user: str, text: str):
        """Append to the room chat."""
        self.text_rooms.config(state=tk.NORMAL)
        self.text_rooms.insert(tk.END, f"[{room}] {user}: {text}\n")
        self.text_rooms.see(tk.END)
        self.text_rooms.config(state=tk.DISABLED)

    def _log_private(self, user: str, text: str):
        """Append to the private chat."""
        self.text_private.config(state=tk.NORMAL)
        self.text_private.insert(tk.END, f"{user}: {text}\n")
        self.text_private.see(tk.END)
        self.text_private.config(state=tk.DISABLED)

    def trigger_emergency(self):
        if not self.connected:
            return
        msg = "CRITICAL THRESHOLD BREACHED! Immediate action required."
        self.send_msg_safe(make_emergency(self.username, msg))

    def play_alarm(self):
        """Play a distinct alarm sound, and flash UI."""
        if HAS_WINSOUND:
            # SOS beep pattern
            threading.Thread(target=self._beep_sequence, daemon=True).start()
        
        self.frame_emergency.pack(side=tk.TOP, fill=tk.X, before=self.notebook)
        # Flash the background
        def flash(count=0):
            if count > 10:
                self.frame_emergency.pack_forget()
                return
            bg = ACCENT_YELLOW if count % 2 == 0 else ACCENT_RED
            self.frame_emergency.config(bg=bg)
            self.lbl_emergency.config(bg=bg)
            self.root.after(300, lambda: flash(count+1))
        flash()

    def _beep_sequence(self):
        for _ in range(3):
            winsound.Beep(1000, 200)
            time.sleep(0.1)

    # =======================================================================
    # Networking & Threading
    # =======================================================================
    def toggle_connection(self):
        if self.connected:
            self.disconnect()
        else:
            self.connect()

    def connect(self):
        host = self.entry_ip.get().strip()
        port = int(self.entry_port.get().strip())
        use_ssl = self.var_ssl.get()
        self.username = self.entry_user.get().strip()

        if not self.username:
            messagebox.showerror("Error", "Username is required.")
            return

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if use_ssl:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.load_verify_locations(SERVER_CERT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_REQUIRED
                self.sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
            else:
                self.sock = raw_sock

            self.sock.connect((host, port))
            
            # Send handshake
            hostname = socket.gethostname()
            send_msg(self.sock, make_connect_msg(self.username, hostname, socket.gethostbyname(hostname)))
            
            # Start threads
            self.stop_event.clear()
            self.receiver_thread = threading.Thread(target=self.receive_loop, daemon=True)
            self.receiver_thread.start()
            
            self.metrics_thread = threading.Thread(target=self.metrics_loop, daemon=True)
            self.metrics_thread.start()
            
            self.connected = True
            self.btn_connect.config(text="Disconnect")
            self.lbl_status.config(text="Connected", foreground=ACCENT_GREEN)
            
            # Request initial file list
            self.send_msg_safe({"type": MsgType.FILE_LIST})
            
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {e}")
            self.disconnect()

    def disconnect(self):
        self.stop_event.set()
        if self.sock:
            try:
                send_msg(self.sock, {"type": MsgType.DISCONNECT})
                self.sock.close()
            except Exception:
                pass
        self.sock = None
        self.connected = False
        
        # Reset UI
        self.btn_connect.config(text="Connect")
        self.lbl_status.config(text="Disconnected", foreground=ACCENT_RED)
        self.listbox_nodes.delete(0, tk.END)
        self.combo_private['values'] = []
        self._log_event("Disconnected from server.")

    def send_msg_safe(self, payload: dict):
        if not self.connected or not self.sock:
            return
        try:
            send_msg(self.sock, payload)
        except Exception as e:
            self._log_event(f"Error sending message: {e}")
            self.disconnect()

    def receive_loop(self):
        while not self.stop_event.is_set():
            try:
                msg = recv_msg(self.sock)
                if msg is None:
                    break
                self.root.after(0, self.handle_message, msg)
            except Exception as e:
                if not self.stop_event.is_set():
                    self.root.after(0, lambda: self._log_event(f"Connection lost: {e}"))
                break
        self.root.after(0, self.disconnect)

    def metrics_loop(self):
        """Simulate real-time metrics and send STATUS_UPDATE."""
        while not self.stop_event.is_set():
            # Random walk for metrics
            self.current_metrics["cpu"] = min(100.0, max(0.0, self.current_metrics["cpu"] + random.uniform(-10, 10)))
            self.current_metrics["bandwidth_mbps"] = min(1000.0, max(0.0, self.current_metrics["bandwidth_mbps"] + random.uniform(-50, 50)))
            
            if self.connected:
                self.send_msg_safe(make_status_update(self.username, self.current_metrics))
                
            self.root.after(0, self.update_dashboard_ui)
            time.sleep(2.0)

    def update_dashboard_ui(self):
        cpu = self.current_metrics["cpu"]
        bw = self.current_metrics["bandwidth_mbps"]
        
        self.progress_cpu['value'] = cpu
        self.lbl_cpu.config(text=f"CPU: {cpu:.1f}%")
        if cpu > 90:
            self.lbl_cpu.config(foreground=ACCENT_RED)
        else:
            self.lbl_cpu.config(foreground=FG_TEXT)
            
        self.progress_bw['value'] = bw
        self.lbl_bw.config(text=f"Bandwidth: {bw:.1f} Mbps")

    # =======================================================================
    # Message Handlers
    # =======================================================================
    def handle_message(self, msg: dict):
        mtype = msg.get("type")
        
        if mtype == MsgType.CONNECT_ACK:
            self._log_event(f"Server says: {msg.get('message')}")
            
        elif mtype == MsgType.CLIENT_LIST:
            self.active_nodes = msg.get("clients", [])
            self.update_active_nodes_ui()
            
        elif mtype == MsgType.STATUS_UPDATE:
            # We could draw other nodes' metrics, for now just log occasionally or show in list
            user = msg.get("username")
            m = msg.get("metrics", {})
            if m.get("cpu", 0) > 95:
                self._log_event(f"ALERT: Node '{user}' CPU critically high ({m.get('cpu'):.1f}%)")
                
        elif mtype in (MsgType.JOIN_ROOM, MsgType.LEAVE_ROOM):
            self._log_event(msg.get("message"))
            
        elif mtype == MsgType.ROOM_MSG:
            self._log_room(msg.get("room"), msg.get("username"), msg.get("text"))
            
        elif mtype == MsgType.PRIVATE_MSG:
            self._log_private(f"[PM from {msg.get('sender')}]", msg.get("text"))
            # Switch to private tab to make it obvious
            self.notebook.select(2)
            
        elif mtype == MsgType.FILE_LIST:
            self.shared_files = msg.get("files", [])
            self.update_files_ui()
            
        elif mtype == MsgType.FILE_SHARE:
            fn = msg.get("filename")
            sz = msg.get("file_size", 0) / 1024
            self._log_event(f"{msg.get('username')} shared a new file: {fn} ({sz:.1f} KB)")
            # Request file list update
            self.send_msg_safe({"type": MsgType.FILE_LIST})
            
        elif mtype == MsgType.FILE_RESPONSE:
            self.save_downloaded_file(msg)
            
        elif mtype == MsgType.EMERGENCY:
            self._log_event(f"EMERGENCY from {msg.get('username')}: {msg.get('message')}")
            self.play_alarm()
            
        elif mtype == MsgType.ERROR:
            self._log_event(f"SERVER ERROR: {msg.get('detail')}")
            messagebox.showwarning("Server Error", msg.get("detail"))

    # =======================================================================
    # UI Actions
    # =======================================================================
    def update_active_nodes_ui(self):
        self.listbox_nodes.delete(0, tk.END)
        names = []
        for n in self.active_nodes:
            display = f"{n['username']} ({n['ip']})"
            self.listbox_nodes.insert(tk.END, display)
            if n['username'] != self.username:
                names.append(n['username'])
        self.combo_private['values'] = names
        if names and not self.combo_private.get():
            self.combo_private.set(names[0])

    def toggle_room_subscription(self, room: str, subscribe: bool):
        if not self.connected:
            return
        mtype = MsgType.JOIN_ROOM if subscribe else MsgType.LEAVE_ROOM
        self.send_msg_safe({"type": mtype, "room": room})

    def send_room_msg(self):
        text = self.entry_room_msg.get().strip()
        room = self.combo_rooms.get()
        if not text or not self.connected:
            return
        if not self.room_vars[room].get():
            messagebox.showwarning("Warning", f"You must join the {room} room first.")
            return
            
        self.send_msg_safe(make_room_msg(self.username, room, text))
        self._log_room(room, "Me", text)
        self.entry_room_msg.delete(0, tk.END)

    def send_private_msg(self):
        text = self.entry_private_msg.get().strip()
        recipient = self.combo_private.get()
        if not text or not recipient or not self.connected:
            return
            
        self.send_msg_safe(make_private_msg(self.username, recipient, text))
        self._log_private(f"[PM to {recipient}]", text)
        self.entry_private_msg.delete(0, tk.END)

    def update_files_ui(self):
        self.listbox_files.delete(0, tk.END)
        for f in self.shared_files:
            sz_kb = f.get('file_size', 0) / 1024
            self.listbox_files.insert(tk.END, f"{f.get('filename')}  |  {sz_kb:.1f} KB  |  By {f.get('username')}")

    def upload_file(self):
        if not self.connected:
            return
        path = filedialog.askopenfilename()
        if not path:
            return
            
        filename = os.path.basename(path)
        file_size = os.path.getsize(path)
        
        # Arbitrary safety limit for memory (e.g. 10MB)
        if file_size > 10 * 1024 * 1024:
            messagebox.showerror("Error", "File too large (limit 10MB).")
            return
            
        try:
            with open(path, "rb") as f:
                data = f.read()
            b64_data = base64.b64encode(data).decode("utf-8")
            self.send_msg_safe(make_file_share(self.username, filename, b64_data, file_size))
            self._log_event(f"Uploaded {filename}.")
        except Exception as e:
            messagebox.showerror("Upload Error", str(e))

    def download_file(self):
        if not self.connected:
            return
        sel = self.listbox_files.curselection()
        if not sel:
            messagebox.showinfo("Select", "Please select a file to download.")
            return
            
        idx = sel[0]
        file_info = self.shared_files[idx]
        filename = file_info.get("filename")
        
        self.send_msg_safe({"type": MsgType.FILE_REQUEST, "filename": filename})
        self._log_event(f"Requested download for {filename}...")

    def save_downloaded_file(self, msg: dict):
        filename = msg.get("filename", "downloaded_file")
        data_b64 = msg.get("file_data", "")
        
        path = filedialog.asksaveasfilename(initialfile=filename)
        if not path:
            return
            
        try:
            data = base64.b64decode(data_b64)
            with open(path, "wb") as f:
                f.write(data)
            self._log_event(f"Saved {filename} successfully.")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorClient(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.disconnect(), root.destroy()))
    root.mainloop()
