document.addEventListener('DOMContentLoaded', () => {
    'use strict';

    // Navegación de Pestañas
    const navItems = document.querySelectorAll('.nav-item');
    const tabPanes = document.querySelectorAll('.tab-pane');

    navItems.forEach(btn => {
        btn.addEventListener('click', () => {
            navItems.forEach(b => b.classList.remove('active'));
            tabPanes.forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            const target = btn.getAttribute('data-tab');
            document.getElementById(target).classList.add('active');
        });
    });

    // Elementos del DOM
    const fileInput = document.getElementById('file-input');
    const fileStatus = document.getElementById('file-status');
    const tableBody = document.querySelector('#main-table tbody');
    const searchInput = document.getElementById('search-filter');
    const severitySelect = document.getElementById('severity-filter');

    const mTotal = document.getElementById('m-total');
    const mCritical = document.getElementById('m-critical');
    const mHigh = document.getElementById('m-high');
    const mMedium = document.getElementById('m-medium');

    const incidentDropdown = document.getElementById('incident-dropdown');
    const singleIncidentView = document.getElementById('single-incident-view');
    const cleaningLog = document.getElementById('cleaning-log');

    let currentSummary = null;

    // Datos simulados por defecto
    const defaultData = [
        { timestamp: "2026-11-06 18:22:10", source_ip: "192.168.1.50", dest_ip: "10.0.0.1", category: "Brute Force SSH", severity: "CRITICAL", action: "BLOQUEADO" },
        { timestamp: "2026-11-06 18:25:00", source_ip: "192.168.1.88", dest_ip: "10.0.0.5", category: "SQL Injection", severity: "HIGH", action: "ALERTADO" },
        { timestamp: "2026-11-06 18:30:14", source_ip: "172.16.0.12", dest_ip: "8.8.8.8", category: "DNS Anómalo", severity: "CRITICAL", action: "BLOQUEADO" },
        { timestamp: "2026-11-06 18:33:01", source_ip: "192.168.1.100", dest_ip: "10.0.0.2", category: "Port Scan", severity: "MEDIUM", action: "REGISTRADO" },
        { timestamp: "2026-11-06 18:35:45", source_ip: "192.168.1.12", dest_ip: "10.0.0.2", category: "Login Correcto", severity: "INFO", action: "PERMITIDO" }
    ];

    function updateUI() {
        currentSummary = window.SIEMEngine.getSummary();
        const { metrics, logs } = currentSummary;

        // Actualizar Métricas
        mTotal.textContent = metrics.total;
        mCritical.textContent = metrics.critical;
        mHigh.textContent = metrics.high;
        mMedium.textContent = metrics.medium;

        // Renderizar Tabla
        renderTable(logs);

        // Renderizar Gráficos
        window.SOCCharts.draw(metrics);

        // Actualizar Selector de Incidentes Individuales
        incidentDropdown.innerHTML = logs.map(l => `<option value="${l.id}">${l.id} - ${l.category} (${l.severity})</option>`).join('');
        if (logs.length > 0) showSingleIncident(logs[0].id);
    }

    function renderTable(logs) {
        const search = searchInput.value.toLowerCase();
        const sevFilter = severitySelect.value;

        const filtered = logs.filter(l => {
            const matchesText = l.sourceIp.includes(search) || l.category.toLowerCase().includes(search) || l.action.toLowerCase().includes(search);
            const matchesSev = sevFilter === 'ALL' || l.severity === sevFilter;
            return matchesText && matchesSev;
        });

        tableBody.innerHTML = filtered.map(l => `
            <tr>
                <td>${l.timestamp}</td>
                <td>${l.sourceIp}</td>
                <td>${l.destinationIp}</td>
                <td>${l.category}</td>
                <td><strong style="color:${l.severity === 'CRITICAL' ? '#ef233c' : '#48cae4'}">${l.severity}</strong></td>
                <td>${l.action}</td>
                <td><button class="btn btn-outline" onclick="window.selectIncident('${l.id}')">Ver</button></td>
            </tr>
        `).join('');
    }

    function showSingleIncident(id) {
        const log = currentSummary.logs.find(l => l.id === id);
        if (!log) return;

        singleIncidentView.innerHTML = `
            <h3>Expediente del Incidente: ${log.id}</h3>
            <p><strong>Fecha/Hora:</strong> ${log.timestamp}</p>
            <p><strong>Origen:</strong> ${log.sourceIp} &rarr; <strong>Destino:</strong> ${log.destinationIp}</p>
            <p><strong>Categoría de Amenaza:</strong> ${log.category}</p>
            <p><strong>Nivel de Severidad:</strong> ${log.severity}</p>
            <p><strong>Acción Aplicada:</strong> ${log.action}</p>
            <p><strong>Descripción Táctica:</strong> ${log.description}</p>
        `;
    }

    window.selectIncident = function(id) {
        document.querySelector('[data-tab="tab-incidents"]').click();
        incidentDropdown.value = id;
        showSingleIncident(id);
    };

    incidentDropdown.addEventListener('change', (e) => showSingleIncident(e.target.value));

    // Filtros de búsqueda
    searchInput.addEventListener('input', () => renderTable(currentSummary.logs));
    severitySelect.addEventListener('change', () => renderTable(currentSummary.logs));

    // Carga de Archivos
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;

        fileStatus.textContent = `Archivo cargado: ${file.name}`;
        const reader = new FileReader();
        reader.onload = function(evt) {
            try {
                const lines = evt.target.result.split('\n');
                const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
                const records = [];

                for (let i = 1; i < lines.length; i++) {
                    if (!lines[i].trim()) continue;
                    const values = lines[i].split(',').map(v => v.trim().replace(/"/g, ''));
                    const obj = {};
                    headers.forEach((h, idx) => obj[h] = values[idx] || '');
                    records.push(obj);
                }
                window.SIEMEngine.loadDataset(records.length > 0 ? records : defaultData);
                updateUI();
            } catch (err) {
                console.error("Error al procesar archivo CSV:", err);
            }
        };
        reader.readAsText(file);
    });

    // Módulo de Limpieza
    document.getElementById('btn-clean-duplicates').addEventListener('click', () => {
        const removed = window.SIEMEngine.removeDuplicates();
        cleaningLog.innerHTML += `<p>[LIMPIEZA]: Se eliminaron ${removed} registros duplicados.</p>`;
        updateUI();
    });

    document.getElementById('btn-purge-info').addEventListener('click', () => {
        const removed = window.SIEMEngine.purgeInfoLogs();
        cleaningLog.innerHTML += `<p>[PURGA]: Se filtraron ${removed} eventos informativos sin riesgo.</p>`;
        updateUI();
    });

    document.getElementById('btn-reset-data').addEventListener('click', () => {
        window.SIEMEngine.resetLogs();
        cleaningLog.innerHTML += `<p>[SISTEMA]: Datos restaurados a su estado inicial.</p>`;
        updateUI();
    });

    // Conexión con IA
    document.getElementById('btn-run-ai').addEventListener('click', async () => {
        const out = document.getElementById('ai-response');
        out.innerHTML = "<em>Conectando con el motor heurístico de IA...</em>";
        const result = await window.SOCAIModule.analyze(currentSummary.metrics, currentSummary.logs);
        out.innerHTML = result;
    });

    // Envío de Email
    document.getElementById('email-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const to = document.getElementById('email-to').value;
        const subject = document.getElementById('email-subject').value;
        const body = document.getElementById('email-body').value;
        const msgDiv = document.getElementById('email-status-msg');

        msgDiv.innerHTML = "<p style='color:var(--accent);'>Enviando alerta...</p>";
        const res = await window.EmailAlertService.send(to, subject, body);
        msgDiv.innerHTML = `<p style='color:var(--success);'>${res.message}</p>`;
    });

    // Exportaciones
    document.getElementById('btn-global-pdf').addEventListener('click', () => {
        window.SOCReportManager.buildGlobalPDF(currentSummary);
    });

    document.getElementById('btn-global-excel').addEventListener('click', () => {
        window.XLSXLite.exportCSV(currentSummary.logs);
    });

    document.getElementById('btn-print-single').addEventListener('click', () => {
        const selectedId = incidentDropdown.value;
        const log = currentSummary.logs.find(l => l.id === selectedId);
        if (log) {
            const html = `
                <div class="card-box">
                    <h2>Expediente de Incidente ${log.id}</h2>
                    <p><strong>Fecha:</strong> ${log.timestamp}</p>
                    <p><strong>Origen:</strong> ${log.sourceIp} &rarr; <strong>Destino:</strong> ${log.destinationIp}</p>
                    <p><strong>Severidad:</strong> ${log.severity}</p>
                    <p><strong>Categoría:</strong> ${log.category}</p>
                    <p><strong>Acción:</strong> ${log.action}</p>
                </div>
            `;
            window.PDFExporter.print(`Incidente ${log.id}`, html);
        }
    });

    // Inicializar
    window.SIEMEngine.loadDataset(defaultData);
    updateUI();
});
