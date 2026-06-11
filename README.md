# Network Nexus: Collaborative Network Monitoring & Alert Dashboard

[![UET Lahore](https://img.shields.io/badge/UET%20Lahore-KSK%20Campus-blue)](https://uet.edu.pk/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0.3-orange.svg)](https://flask.palletsprojects.com/)
[![Socket.IO](https://img.shields.io/badge/Socket.IO-5.3.6-black.svg)](https://socket.io/)

**Network Nexus** is a real-time, distributed Network Operations Center (NOC) simulator and monitoring application. It bridges low-level socket programming and high-level web interface technologies to enable multiple connected administrators to monitor network health metrics, subscribe to specific alert rooms, share log evidence, and coordinate incident response in real time.

This project was developed for the **Computer Networks Lab Course** at the **University of Engineering and Technology, Lahore (KSK Campus)**, Department of Computer Science.

---

## 👥 Contributors (Session 2025)

*   **Irfan Shaukat** — `2025(S)-SE-04`
*   **Abdul Hadi** — `2025(S)-SE-05`
*   **Bilal Ahmad Shami** — `2025(S)-SE-23`

**Submitted To:** Ma'am Shanfa Irum  
**Institution:** UET Lahore (KSK Campus), Department of Computer Science  

---

## 🌟 Key Features

1.  **Real-Time Telemetry & Monitoring:** Broadcasts and tracks live node metrics including CPU utilization, bandwidth consumption, RAM usage, temperature, and packet loss.
2.  **Topic-Based Alert Rooms:** Pub/sub channels (`CPU`, `Bandwidth`, `Security`) allow administrators to filter notifications according to their area of responsibility without background noise.
3.  **Global Emergency Broadcasts:** Automatically triggers a full-screen, non-dismissible red overlay alert on all active dashboards when server metrics exceed critical thresholds (e.g., CPU > 90%, Temp > 80°C).
4.  **Private Direct Messaging:** Inter-operator private chat for direct escalation and collaborative debugging.
5.  **Evidence & File Sharing:** Secure file transfer mechanism to share logs and screenshots across nodes using Base64-encoded payloads over TCP.
6.  **TLS/SSL Encryption:** Built-in capability for secure encrypted communications (using standard TLS/SSL sockets) with auto-generating self-signed certificates.
7.  **Dynamic Concurrency Simulator:** Spawns multiple mock nodes (Alice, Bob, Carol) to test server synchronization and message load handling.
8.  **Automated Integration Test Suite:** Dedicated test runner validating all protocol types (multi-client handshake, discovery, messaging, file sharing, and emergencies).

---

## 🏗️ System Architecture

Network Nexus implements a **Star Topology** (Client-Server architecture) where all connected node proxies route communication through a central backend message broker.

```
                   +---------------------------------------+
                   |  Central Network Monitoring Server    |
                   |          (server.py:9500)             |
                   +---------------------------------------+
                    /                  |                  \
                   /                   |                   \
      [TCP Socket / SSL]       [TCP Socket / SSL]    [TCP Socket / SSL]
                 /                     |                     \
                v                      v                      v
        +---------------+      +---------------+      +---------------+
        |  Client Node  |      |  Client Node  |      |  Client Node  |
        |  (client.py)  |      |  (client.py)  |      |  (client.py)  |
        +---------------+      +---------------+      +---------------+
                |                      |                      |
          [Socket.IO]            [Socket.IO]            [Socket.IO]
                |                      |                      |
                v                      v                      v
        +---------------+      +---------------+      +---------------+
        |  Glassmorphic |      |  Glassmorphic |      |  Glassmorphic |
        | Web Dashboard |      | Web Dashboard |      | Web Dashboard |
        | (Port 8080)   |      | (Port 8080)   |      | (Port 8080)   |
        +---------------+      +---------------+      +---------------+
```

### 🛰️ Web-Bridge Proxy Pattern
Because web browsers cannot open raw TCP sockets directly, each node runs `client.py` as a **Local Proxy (Web Bridge)**:
*   The **Frontend** (Glassmorphic Web Dashboard) communicates with `client.py` via `Flask-SocketIO` (WebSockets).
*   The **Proxy** (`client.py`) translates WebSocket events into raw TCP/SSL socket packets and forwards them to `server.py`.
*   Incoming raw TCP packets are parsed and pushed back to the browser.

---

## 📁 Repository Structure

```
Network Monitoring System/
├── client.py            # Web-Bridge client proxy, simulator & CLI integration test suite
├── server.py            # Central TCP/SSL Server, state/file registry & certificate generator
├── run.py               # Launcher script that boots all services and launches dashboard
├── requirements.txt     # Python application dependencies
├── server.crt           # Generated TLS certificate
├── server.key           # Generated TLS private key
├── server_logs.txt      # Main server execution log file
└── static/              # Dashboard Web Frontend
    ├── index.html       # Stunning glassmorphic web dashboard
    ├── script.js        # Websocket handlers, metrics charts, and DOM controller
    └── style.css        # Premium custom stylesheet with micro-animations & dark styling
```

---

## 📨 Custom Protocol Design

The custom application-layer protocol is framed with a **4-byte big-endian length prefix** to handle TCP fragmentation, followed by a JSON payload:

`[ 4-Byte Payload Length (Big-Endian) ] [ JSON Message Payload ]`

### Supported Message Types

| Message Type | Sender | Purpose |
| :--- | :--- | :--- |
| `connect` | Client | Initiates session handshake, submits hostname & IP address |
| `connect_ack` | Server | Confirms registration, sends welcome message & list of rooms |
| `disconnect` | Client | Clean disconnection signal |
| `client_list` | Server | Broadcasts updated list of active network administrators |
| `status_update` | Client | Sends metrics payload (CPU, bandwidth, temp, RAM) |
| `join_room` | Client | Subscribes client to a topic-based alert room (`CPU`/`Bandwidth`/`Security`) |
| `leave_room` | Client | Unsubscribes client from a room |
| `room_msg` | Both | Transmits chat/logs within a specific alert room |
| `private_msg` | Client | Direct messaging between two administrators |
| `file_share` | Client | Uploads base64 file chunk to the server |
| `file_list` | Both | Requests/Distributes metadata for all shared files |
| `file_request` | Client | Requests binary file download from the server |
| `file_response` | Server | Relays file payload back to requesting client |
| `emergency` | Both | System-wide critical alert broadcast |
| `error` | Server | Signals protocol exception or registration rejection |

---

## 🚀 Getting Started

### 📋 Prerequisites

Make sure you have **Python 3.10 or higher** installed. Install dependencies using:

```bash
pip install -r requirements.txt
```

*Note: The dependencies include `Flask`, `Flask-SocketIO`, and `eventlet` for concurrent execution.*

### 🛠️ Running the Dashboard (Launcher)

The easiest way to run the entire system is through the startup launcher `run.py`:

```bash
python run.py
```

This script:
1.  Starts the central monitoring server (`server.py`) on background port `9500`.
2.  Starts the web proxy client bridge (`client.py`) on local port `8080`.
3.  Automatically opens the **Glassmorphic Web Dashboard** in your default web browser (`http://localhost:8080`).

To run with **TLS/SSL Encryption** enabled:
```bash
python run.py --ssl
```

---

## 🧪 Testing & Verification

### Running Automated Integration Tests
The project features an automated backend integration test suite. To execute it:

1.  Start the Server:
    ```bash
    python server.py
    ```
2.  Run the tests using the client's test flag in another terminal:
    ```bash
    python client.py --test
    ```

For testing over an encrypted channel:
```bash
python server.py --ssl
python client.py --test --ssl
```

---

## 🛡️ License

This project was built for educational purposes as part of the Computer Networks (CN) Theory & Lab Project curriculum at **UET Lahore (KSK)**.
