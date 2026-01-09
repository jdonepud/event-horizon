document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const analysisLog = document.getElementById('analysisLog');
    const chainViz = document.getElementById('chainViz');

    const addLog = (msg, type = 'info') => {
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        const now = new Date();
        const ts = now.toTimeString().split(' ')[0];
        entry.innerHTML = `<span class="timestamp">[${ts}]</span> <span class="msg">${msg}</span>`;
        analysisLog.prepend(entry);
    };

    const processData = (file) => {
        addLog(`Ingesting ${file.name}...`, 'info');
        setTimeout(() => {
            addLog(`Parsing vector strings for ${file.name}...`, 'info');
            setTimeout(() => {
                addLog(`CRITICAL: Vector Chaining detected (CVE-2024-001 -> CVE-2024-002)`, 'danger');
                updateDashboard();
                addLog(`Triage complete. 24 vulns processed.`, 'success');
            }, 1000);
        }, 800);
    };

    const updateDashboard = () => {
        const nodes = document.querySelectorAll('.node');
        nodes.forEach((node, i) => {
            setTimeout(() => {
                node.style.borderColor = i === 1 ? '#ff2d55' : '#007aff';
                node.style.boxShadow = `0 0 20px ${i === 1 ? 'rgba(255,45,85,0.4)' : 'rgba(0,122,255,0.4)'}`;
            }, i * 300);
        });
    };

    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) processData(e.target.files[0]);
    });
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--accent)';
    });
    dropZone.addEventListener('dragleave', () => {
        dropZone.style.borderColor = 'var(--border)';
    });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--border)';
        const files = e.dataTransfer.files;
        if (files.length > 0) processData(files[0]);
    });
});
