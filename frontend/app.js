const API_URL = "http://localhost:8000";
let ws = null;

function connectWebSocket() {
    ws = new WebSocket(`ws://localhost:8000/ws/scan`);
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        updateScanProgress(data);
    };
}

async function startScan() {
    const scanBtn = document.getElementById("scanBtn");
    const progressDiv = document.getElementById("scanProgress");
    
    scanBtn.disabled = true;
    progressDiv.style.display = "block";
    
    try {
        connectWebSocket();
        
        const response = await fetch(`${API_URL}/scan`, { method: "POST" });
        const result = await response.json();
        
        if (response.ok) {
            updateScanResults(result);
            fetchAll();
        }
    } catch (error) {
        console.error("Scan error:", error);
        document.getElementById("scanStatus").textContent = "Scan failed";
    } finally {
        scanBtn.disabled = false;
        setTimeout(() => {
            progressDiv.style.display = "none";
        }, 2000);
    }
}

function updateScanProgress(data) {
    const progressFill = document.getElementById("progressFill");
    const scanStatus = document.getElementById("scanStatus");
    
    progressFill.style.width = `${data.progress}%`;
    
    if (data.current_device) {
        scanStatus.textContent = `Scanning: ${data.current_device}`;
    } else {
        scanStatus.textContent = data.status === "complete" ? "✓ Scan complete" : "Scanning...";
    }
}

function updateScanResults(result) {
    console.log("Scan results:", result);
}

async function fetchDevices() {
    try {
        const response = await fetch(`${API_URL}/devices`);
        const data = await response.json();
        const devices = data.devices || [];

        const list = document.getElementById("device-list");
        if (devices.length === 0) {
            list.innerHTML = '<p class="loading">No devices found</p>';
            return;
        }

        list.innerHTML = devices.map(d => `
            <div class="device-item ${d.is_suspicious ? 'suspicious' : ''}">
                <div class="device-name">${d.hostname || "Unknown"}</div>
                <div class="device-info">
                    <div>IP: ${d.ip_address}</div>
                    <div>MAC: ${d.mac_address}</div>
                </div>
                ${d.is_suspicious ? '<div class="device-suspicious">⚠️ FOREIGN DEVICE</div>' : ''}
            </div>
        `).join("");
    } catch (error) {
        console.error("Error fetching devices:", error);
    }
}

async function fetchAlerts() {
    try {
        const response = await fetch(`${API_URL}/alerts?limit=15`);
        const data = await response.json();
        const alerts = data.alerts || [];

        const list = document.getElementById("alert-list");
        if (alerts.length === 0) {
            list.innerHTML = '<p class="loading">No alerts</p>';
            return;
        }

        list.innerHTML = alerts.map(a => `
            <div class="alert-item ${a.severity.toLowerCase()}">
                <div class="alert-type">
                    ${a.alert_type}
                    <span class="severity-badge severity-${a.severity.toLowerCase()}">${a.severity}</span>
                </div>
                <div class="alert-message">${a.message}</div>
                <div class="alert-time">${new Date(a.timestamp).toLocaleString()}</div>
            </div>
        `).join("");
    } catch (error) {
        console.error("Error fetching alerts:", error);
    }
}

async function fetchStats() {
    try {
        const response = await fetch(`${API_URL}/stats`);
        const data = await response.json();

        document.getElementById("stat-devices").textContent = data.total_devices || 0;
        document.getElementById("stat-suspicious").textContent = data.suspicious_devices || 0;
        document.getElementById("stat-alerts").textContent = data.total_alerts || 0;

        const threatLevel = document.getElementById("threat-level");
        const threatCard = document.getElementById("threat-card");
        const levelText = (data.threat_level || "safe").toUpperCase();
        
        threatLevel.textContent = levelText;
        threatLevel.className = data.threat_level || "safe";
        
        if (levelText === "CRITICAL") {
            threatCard.style.borderColor = "var(--neon-red)";
        } else if (levelText === "HIGH") {
            threatCard.style.borderColor = "var(--neon-yellow)";
        } else {
            threatCard.style.borderColor = "var(--neon-cyan)";
        }
    } catch (error) {
        console.error("Error fetching stats:", error);
    }
}

function fetchAll() {
    fetchStats();
    fetchDevices();
    fetchAlerts();
}

window.addEventListener("load", () => {
    fetchAll();
    setInterval(fetchAll, 5000);
});