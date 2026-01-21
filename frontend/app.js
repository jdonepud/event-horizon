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

    const reachabilityValue = document.getElementById('reachabilityValue');
    const mitreValue = document.getElementById('mitreValue');

    const API_URL = 'http://localhost:8000';

    const checkEngineStatus = async () => {
        try {
            const resp = await fetch(`${API_URL}/`);
            if (resp.ok) {
                document.querySelector('.status-badge').innerHTML = '<span class="pulse"></span> ENGINE ONLINE';
                addLog('Backend engine connected and ready.', 'success');
            }
        } catch (e) {
            document.querySelector('.status-badge').innerHTML = '<span class="pulse" style="background: var(--danger); box-shadow: 0 0 10px var(--danger);"></span> ENGINE OFFLINE';
            addLog('Warning: Backend engine unreachable. Using local simulation.', 'info');
        }
    };

    checkEngineStatus();

    const processData = async (file) => {
        addLog(`Ingesting ${file.name}...`, 'info');

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch(`${API_URL}/ingest/csv`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) throw new Error('Backend error');

            const data = await response.json();
            addLog(`Received analysis for ${data.summary.total_processed} vulnerabilities.`, 'success');

            if (data.attack_path_analysis) {
                if (data.summary.is_critical) {
                    addLog(`CRITICAL: Vector Chaining detected: ${data.attack_path_analysis.path}`, 'danger');
                } else {
                    addLog(`Chain analysis complete: ${data.attack_path_analysis.path}`, 'info');
                }
            }

            updateDashboard({
                reachability: data.individual_reports[0]?.reachability || 'Calculated Profile',
                mitre: data.summary.is_critical ? 'T1190 (Exploit Public-Facing Application)' : 'T1059 (Command/Script)',
                vulns: data.summary.total_processed,
                isCritical: data.summary.is_critical
            });

        } catch (error) {
            addLog(`Backend unavailable, falling back to simulation...`, 'info');
            // Mock simulation for demonstration if backend is down
            setTimeout(() => {
                const isCritical = file.name.includes('critical');
                updateDashboard({
                    reachability: isCritical ? 'Critical Infrastructure' : 'Isolated Network',
                    mitre: isCritical ? 'T1190' : 'T1059',
                    vulns: 3,
                    isCritical: isCritical
                });
                addLog(`Simulation complete for ${file.name}.`, 'success');
            }, 1000);
        }
    };

    const updateDashboard = (profile) => {
        reachabilityValue.innerText = profile.reachability;
        mitreValue.innerText = profile.mitre;

        // Dynamic UI updates for visual flair
        const nodes = document.querySelectorAll('.node');
        nodes.forEach((node, i) => {
            setTimeout(() => {
                const color = profile.isCritical ? '#ff2d55' : '#007aff';
                node.style.borderColor = color;
                node.style.boxShadow = `0 0 20px ${color}66`;
            }, i * 200);
        });
    };

    dropZone.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            processData(e.target.files[0]);
        }
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
        if (files.length > 0) {
            processData(files[0]);
        }
    });
});
