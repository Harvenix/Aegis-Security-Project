const feedPanel = document.getElementById('live-feed');
const summaryPanel = document.getElementById('summary');
const orb = document.querySelector('.orb');
const socket = io("http://127.0.0.1:5000");

socket.on('connect', () => console.log('Successfully connected to Aegis server!'));
socket.on('new_process', (data) => {
    addLogEntry(data);
    triggerAlertVisuals(data.analysis);
});

function addLogEntry(eventData) {
    const logEntry = document.createElement('div');
    let alert_level = 'clear';
    if (eventData.analysis.includes('High Alert')) alert_level = 'warning';
    if (eventData.analysis.includes('CRITICAL')) alert_level = 'critical';
    logEntry.className = `log-entry ${alert_level}`;

    const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false });
    logEntry.innerHTML = `
        <span class="log-time">[${timestamp}]</span>
        <span class="log-name">${eventData.process_name}</span>
        <span class="log-status status-${alert_level}">${eventData.analysis.toUpperCase()}</span>
    `;

    logEntry.addEventListener('click', () => updateThreatAnalysisPanel(eventData));
    feedPanel.insertBefore(logEntry, feedPanel.children[1]);
}

function updateThreatAnalysisPanel(eventData) {
    summaryPanel.innerHTML = '<h3>// THREAT ANALYSIS //</h3>';
    const detailsContainer = document.createElement('div');
    detailsContainer.className = 'details-container';

    const detailsToShow = {
        "Process": eventData.process_name,
        "VirusTotal": eventData.virustotal_score,
        "Signature": eventData.signer_status,
        "SHA256 Hash": eventData.hash_sha256,
        "Full Path": eventData.path,
        "User": eventData.username,
    };

    let detailsHTML = `<h4>${eventData.process_name}</h4>`;
    for (const [key, value] of Object.entries(detailsToShow)) {
        if (value) { // Only show a row if the value exists
            detailsHTML += `
                <div class="detail-row">
                    <span class="detail-key">${key}</span>
                    <span class="detail-value">${value}</span>
                </div>
            `;
        }
    }
    detailsContainer.innerHTML = detailsHTML;
    summaryPanel.appendChild(detailsContainer);
}

function triggerAlertVisuals(analysis) {
    // This function remains the same
    if (analysis.includes('High Alert')) {
        orb.style.background = 'radial-gradient(circle, #ffc107, #0a0e1a 70%)';
    } else if (analysis.includes('CRITICAL')) {
        orb.style.background = 'radial-gradient(circle, #dc3545, #0a0e1a 70%)';
    }
    setTimeout(() => {
        orb.style.background = 'radial-gradient(circle, #00bfff, #0a0e1a 70%)';
    }, 5000);
}