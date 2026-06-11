const socket = io();

// State
let connected = false;
let myUsername = "";

// Initialize Chart.js
const chartCtx = document.getElementById('metricsChart').getContext('2d');
const metricsChart = new Chart(chartCtx, {
    type: 'line',
    data: {
        labels: [],
        datasets: [
            {
                label: 'CPU (%)',
                data: [],
                borderColor: '#38bdf8',
                backgroundColor: 'rgba(56, 189, 248, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.3
            },
            {
                label: 'Bandwidth (Mbps)',
                data: [],
                borderColor: '#34d399',
                backgroundColor: 'rgba(52, 211, 153, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.3
            }
        ]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            x: {
                grid: { display: false },
                ticks: { color: '#94a3b8', maxTicksLimit: 8 }
            },
            y: {
                beginAtZero: true,
                ticks: { color: '#94a3b8' }
            }
        },
        plugins: {
            legend: {
                labels: { color: '#f8fafc', font: { family: 'Outfit' } }
            }
        }
    }
});

function updateChart(cpu, bandwidth) {
    const maxDataPoints = 15;
    const timeString = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    metricsChart.data.labels.push(timeString);
    metricsChart.data.datasets[0].data.push(cpu);
    metricsChart.data.datasets[1].data.push(bandwidth);
    
    if (metricsChart.data.labels.length > maxDataPoints) {
        metricsChart.data.labels.shift();
        metricsChart.data.datasets[0].data.shift();
        metricsChart.data.datasets[1].data.shift();
    }
    
    metricsChart.update();
}

// Generate a random username on load
document.getElementById('inp-user').value = "User_" + Math.floor(Math.random() * 1000);

// Audio context for emergency alarm beep
const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
function playBeep() {
    const oscillator = audioCtx.createOscillator();
    const gainNode = audioCtx.createGain();
    oscillator.connect(gainNode);
    gainNode.connect(audioCtx.destination);
    oscillator.type = 'square';
    oscillator.frequency.value = 1000;
    gainNode.gain.setValueAtTime(0.1, audioCtx.currentTime);
    oscillator.start();
    oscillator.stop(audioCtx.currentTime + 0.2);
}

// -----------------------------------------------------------------------------
// Socket.IO Client Events
// -----------------------------------------------------------------------------

socket.on('bridge_connected', (data) => {
    connected = true;
    myUsername = data.username;
    
    document.getElementById('btn-connect').innerText = "Disconnect";
    document.getElementById('inp-host').disabled = true;
    document.getElementById('inp-port').disabled = true;
    document.getElementById('inp-user').disabled = true;
    document.getElementById('chk-ssl').disabled = true;
    
    const badge = document.getElementById('conn-status');
    badge.innerText = "Connected";
    badge.className = "status-badge online";
    
    // Show simulation button
    document.getElementById('btn-simulate').style.display = "inline-block";
    
    logEvent("System", `Successfully bridged to server at ${data.host}:${data.port}`);
});

socket.on('bridge_disconnected', (data) => {
    connected = false;
    document.getElementById('btn-connect').innerText = "Connect";
    document.getElementById('inp-host').disabled = false;
    document.getElementById('inp-port').disabled = false;
    document.getElementById('inp-user').disabled = false;
    document.getElementById('chk-ssl').disabled = false;
    
    const badge = document.getElementById('conn-status');
    badge.innerText = "Disconnected";
    badge.className = "status-badge offline";
    
    // Hide and reset simulation button
    const btnSim = document.getElementById('btn-simulate');
    btnSim.style.display = "none";
    btnSim.innerText = "Simulate Concurrency";
    btnSim.className = "btn simulation";
    simulationRunning = false;
    
    document.getElementById('list-nodes').innerHTML = "";
    document.getElementById('sel-private').innerHTML = "";
    
    logEvent("System", `Disconnected: ${data.reason}`);
});

socket.on('client_list', (data) => {
    const list = document.getElementById('list-nodes');
    const select = document.getElementById('sel-private');
    list.innerHTML = "";
    select.innerHTML = "";
    
    data.clients.forEach(c => {
        const li = document.createElement('li');
        li.innerHTML = `<span>${c.username}</span> <span style="color:var(--text-secondary); font-size:12px">${c.ip}</span>`;
        list.appendChild(li);
        
        if (c.username !== myUsername) {
            const opt = document.createElement('option');
            opt.value = c.username;
            opt.innerText = c.username;
            select.appendChild(opt);
        }
    });
});

socket.on('metrics_update', (data) => {
    // Only update our own dashboard metrics from local simulation
    document.getElementById('val-cpu').innerText = data.cpu.toFixed(1) + "%";
    document.getElementById('val-bw').innerText = data.bandwidth_mbps.toFixed(1) + " Mbps";
    
    updateChart(data.cpu, data.bandwidth_mbps);
});

socket.on('room_msg', (data) => {
    const box = document.getElementById('box-rooms');
    const msg = document.createElement('div');
    msg.className = data.username === "SERVER" ? "chat-msg server" : "chat-msg";
    msg.innerHTML = `[${data.room}] <strong>${data.username}:</strong> ${data.text}`;
    box.appendChild(msg);
    box.scrollTop = box.scrollHeight;
});

socket.on('private_msg', (data) => {
    const box = document.getElementById('box-private');
    const msg = document.createElement('div');
    msg.className = "chat-msg";
    msg.innerHTML = `<span style="color:var(--accent-purple)">[From ${data.sender}]:</span> ${data.text}`;
    box.appendChild(msg);
    box.scrollTop = box.scrollHeight;
});

socket.on('file_list', (data) => {
    const list = document.getElementById('list-files');
    list.innerHTML = "";
    data.files.forEach(f => {
        const li = document.createElement('li');
        const sz = (f.file_size / 1024).toFixed(1);
        li.innerHTML = `
            <div><strong>${f.filename}</strong> <br> <small>${sz} KB | By ${f.username}</small></div>
            <button onclick="downloadFile('${f.filename}')">Get</button>
        `;
        list.appendChild(li);
    });
});

function showPreview(filename, fileDataB64, fileType) {
    const modal = document.getElementById('preview-modal');
    const title = document.getElementById('preview-title');
    const body = document.getElementById('preview-body');
    
    title.innerText = `File Preview: ${filename}`;
    body.innerHTML = "";
    
    const isImage = fileType.startsWith('image/') || /\.(jpg|jpeg|png|gif|webp)$/i.test(filename);
    const isText = fileType.startsWith('text/') || /\.(txt|json|log|py|md|html|css|js)$/i.test(filename);
    
    if (isImage) {
        const img = document.createElement('img');
        img.src = `data:${fileType};base64,${fileDataB64}`;
        body.appendChild(img);
    } else if (isText) {
        const pre = document.createElement('pre');
        try {
            pre.innerText = atob(fileDataB64);
        } catch (e) {
            pre.innerText = decodeURIComponent(escape(atob(fileDataB64)));
        }
        body.appendChild(pre);
    } else {
        body.innerHTML = `<p style="color:var(--text-secondary); text-align:center;">Binary file preview not supported.<br>The file has been saved to your downloads folder.</p>`;
    }
    
    modal.classList.remove('hidden');
}

function closePreviewModal(event) {
    document.getElementById('preview-modal').classList.add('hidden');
}

socket.on('file_receive', (data) => {
    logEvent("System", `File downloaded successfully: ${data.filename}`);
    
    // Trigger browser download via Blob
    const byteCharacters = atob(data.file_data);
    const byteNumbers = new Array(byteCharacters.length);
    for (let i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteNumbers);
    const blob = new Blob([byteArray]);
    
    const link = document.createElement('a');
    link.href = window.URL.createObjectURL(blob);
    link.download = data.filename;
    link.click();
    
    // Show preview modal
    showPreview(data.filename, data.file_data, data.file_type || 'application/octet-stream');
});

socket.on('emergency', (data) => {
    logEvent("EMERGENCY", `${data.username}: ${data.message}`);
    const banner = document.getElementById('emergency-banner');
    document.getElementById('emergency-msg').innerText = `[${data.username}] ${data.message}`;
    banner.className = "";
    
    // Play 3 beeps
    playBeep();
    setTimeout(playBeep, 400);
    setTimeout(playBeep, 800);
});

socket.on('event_log', (data) => {
    logEvent("Alert", data.text);
});

// -----------------------------------------------------------------------------
// UI Actions -> Socket.IO Emit
// -----------------------------------------------------------------------------

function logEvent(tag, text) {
    const box = document.getElementById('box-events');
    const d = new Date().toLocaleTimeString();
    box.innerHTML += `<div>[${d}] [${tag}] ${text}</div>`;
    box.scrollTop = box.scrollHeight;
}

function toggleConnection() {
    if (connected) {
        socket.emit('bridge_disconnect');
    } else {
        const host = document.getElementById('inp-host').value;
        const port = document.getElementById('inp-port').value;
        const user = document.getElementById('inp-user').value;
        const ssl = document.getElementById('chk-ssl').checked;
        
        if(!user) return alert("Username required");
        socket.emit('bridge_connect', { host, port, username: user, use_ssl: ssl });
    }
}

function toggleRoom(room, join) {
    socket.emit('room_toggle', { room, action: join ? 'join' : 'leave' });
}

function sendRoomMsg() {
    const inp = document.getElementById('inp-room-msg');
    const room = document.getElementById('sel-room').value;
    if(!inp.value.trim() || !connected) return;
    
    socket.emit('send_room', { room, text: inp.value });
    
    // Echo locally
    const box = document.getElementById('box-rooms');
    box.innerHTML += `<div class="chat-msg">[${room}] <strong>Me:</strong> ${inp.value}</div>`;
    box.scrollTop = box.scrollHeight;
    
    inp.value = "";
}

function sendPrivateMsg() {
    const inp = document.getElementById('inp-private-msg');
    const recipient = document.getElementById('sel-private').value;
    if(!inp.value.trim() || !recipient || !connected) return;
    
    socket.emit('send_private', { recipient, text: inp.value });
    
    // Echo locally
    const box = document.getElementById('box-private');
    box.innerHTML += `<div class="chat-msg"><span style="color:var(--accent-purple)">[To ${recipient}]:</span> ${inp.value}</div>`;
    box.scrollTop = box.scrollHeight;
    
    inp.value = "";
}

function handleEnter(e, func) {
    if (e.key === 'Enter') func();
}

function uploadFile() {
    const file = document.getElementById('inp-file').files[0];
    if(!file || !connected) return;
    
    if (file.size > 10 * 1024 * 1024) {
        return alert("File too large. Max 10MB limit.");
    }
    
    const reader = new FileReader();
    reader.onload = function(evt) {
        // evt.target.result is a Data URL like "data:image/png;base64,iVBORw0KGgo..."
        const b64 = evt.target.result.split(',')[1]; 
        
        socket.emit('upload_file', {
            filename: file.name,
            file_data: b64,
            file_size: file.size,
            file_type: file.type
        });
        
        logEvent("System", `Uploaded file: ${file.name}`);
    };
    reader.readAsDataURL(file);
}

function downloadFile(filename) {
    if(!connected) return;
    logEvent("System", `Requesting download for: ${filename}`);
    socket.emit('download_file', { filename });
}

function triggerEmergency() {
    if(!connected) return;
    socket.emit('trigger_emergency', { message: "CRITICAL THRESHOLD BREACHED! Immediate action required." });
}

function dismissEmergency() {
    document.getElementById('emergency-banner').className = "hidden";
}

// -----------------------------------------------------------------------------
// Simulation Logic
// -----------------------------------------------------------------------------
let simulationRunning = false;

function toggleSimulation() {
    if (!connected) return;
    if (simulationRunning) {
        socket.emit('simulate_concurrency', { action: 'stop' });
    } else {
        socket.emit('simulate_concurrency', { action: 'start' });
    }
}

socket.on('simulation_state', (data) => {
    simulationRunning = data.running;
    const btn = document.getElementById('btn-simulate');
    if (simulationRunning) {
        btn.innerText = "Stop Simulation";
        btn.className = "btn simulation running";
    } else {
        btn.innerText = "Simulate Concurrency";
        btn.className = "btn simulation";
    }
});
