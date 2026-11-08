/**
 * Controlador de la interfaz del SOC.
 * Gestiona navegación de vistas, carga de archivos, renderizado de tablas,
 * métricas, limpieza de datos, informes, IA y correo. Expone: window.SOCController
 */
(function () {
  'use strict';

  /* ---------- Elementos del DOM ---------- */
  const navButtons = document.querySelectorAll('.tab-btn');
  const viewPanes = document.querySelectorAll('.tab-pane');

  const fileInput = document.getElementById('log-file');
  const uploadStatus = document.getElementById('upload-status');

  const statTotal = document.getElementById('stat-total');
  const statCritical = document.getElementById('stat-critical');
  const statHigh = document.getElementById('stat-high');
  const statMedium = document.getElementById('stat-medium');

  // Estadísticas de la pestaña de heurística
  const ahTotal = document.getElementById('ah-total');
  const ahCritical = document.getElementById('ah-critical');
  const ahHigh = document.getElementById('ah-high');
  const ahMedium = document.getElementById('ah-medium');

  const searchFilter = document.getElementById('search-filter');
  const severityFilter = document.getElementById('severity-filter');
  const logTableBody = document.querySelector('#log-table tbody');

  const incidentSelect = document.getElementById('incident-list');
  const viewIncidentBtn = document.getElementById('btn-view-incident');
  const incidentDetail = document.getElementById('incident-detail');

  const emailForm = document.getElementById('email-form');
  const emailTo = document.getElementById('email-to');
  const emailSubject = document.getElementById('email-subject');
  const emailBody = document.getElementById('email-body');
  const emailFeedback = document.getElementById('email-feedback');

  const aiRunBtn = document.getElementById('btn-run-ai');
  const aiResult = document.getElementById('ai-result');

  // Elementos de IA real (Google Gemini)
  const geminiKeyInput = document.getElementById('gemini-key');
  const geminiModelSelect = document.getElementById('gemini-model');
  const btnCheckGemini = document.getElementById('btn-check-gemini');
  const geminiStatus = document.getElementById('gemini-status');

  const downloadPdfBtn = document.getElementById('btn-download-pdf');

  // Botones de descarga en pestaña Descargas (seleccionados por data-type)
  const downloadExecBtn = document.querySelector('.download-btn[data-type="ejecutivo"]');
  const downloadTechBtn = document.querySelector('.download-btn[data-type="tecnico"]');
  const downloadCombinedBtn = document.querySelector('.download-btn[data-type="combinado"]');
  const downloadStatus = document.getElementById('download-status');

  /* ---------- Estado de la aplicación ---------- */
  let currentDataset = null;   // { events, incidents, stats, alerts }
  let workingEvents = [];      // eventos tras operaciones de limpieza
  let geminiApiKey = '';       // clave API del usuario (solo en memoria)
  let geminiModel = 'gemini-2.5-flash';
  let geminiConnected = false;
  let tableSort = { column: null, direction: 'asc' };  // ordenamiento de la tabla de heurística

  /* ---------- Navegación entre vistas ---------- */
  function switchView() {
    navButtons.forEach((btn) => btn.classList.remove('active'));
    viewPanes.forEach((pane) => pane.classList.remove('active'));
    this.classList.add('active');
    const targetId = this.getAttribute('data-view');
    document.getElementById(targetId).classList.add('active');
  }
  navButtons.forEach((btn) => btn.addEventListener('click', switchView));

  /* ---------- Utilidades ---------- */
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text ?? '';
    return div.innerHTML;
  }

  function showConsole(message, type = 'info') {
    const line = document.createElement('p');
    line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    line.style.color = type === 'ok' ? '#22d3ee' : type === 'err' ? '#f87171' : '#22d3ee';
    cleanLog.appendChild(line);
    cleanLog.scrollTop = cleanLog.scrollHeight;
  }

  function formatDateTime(epoch) {
    if (!epoch) return '';
    return new Date(epoch).toISOString().slice(0, 19).replace('T', ' ');
  }

  function severityBadgeClass(severity) {
    switch (String(severity).toUpperCase()) {
      case 'CRITICAL': return 'sev-critical';
      case 'HIGH': return 'sev-high';
      case 'MEDIUM': return 'sev-medium';
      default: return 'sev-info';
    }
  }

  /* ---------- Carga de archivos ---------- */
  fileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    uploadStatus.textContent = 'Procesando ' + escapeHtml(file.name) + '…';

    try {
      let rawRows;
      if (file.name.toLowerCase().endsWith('.csv')) {
        const text = await LogImporter.readText(file);
        const parsed = LogImporter.parseCsv(text);
        rawRows = parsed.rows;
      } else if (file.name.toLowerCase().endsWith('.xlsx')) {
        const buffer = await LogImporter.readBuffer(file);
        const xlsx = LogImporter.parseXlsxBuffer(buffer);
        rawRows = await xlsx.buildRows();
        // Convertir filas de arrays a objetos usando la primera fila como cabecera
        if (rawRows.length > 0) {
          const headers = rawRows[0];
          rawRows = rawRows.slice(1).map((row) => {
            const obj = {};
            headers.forEach((h, i) => { obj[h] = row[i] !== undefined ? row[i] : ''; });
            return obj;
          });
        }
      } else {
        throw new Error('Formato de archivo no soportado. Use .csv o .xlsx');
      }

      if (!rawRows || rawRows.length === 0) throw new Error('El archivo no contiene filas de datos.');

      const analysis = SIEMAnalyzer.analyze(rawRows);
      currentDataset = analysis;
      workingEvents = [...analysis.events];

      uploadStatus.textContent = `Cargado: ${escapeHtml(file.name)} · ${analysis.stats.total} eventos · ${analysis.incidents.length} incidentes`;
      refreshMetrics();
      renderLogTable();
      renderIncidentSelector();
      refreshCharts();
    } catch (err) {
      uploadStatus.textContent = 'Error: ' + escapeHtml(err.message);
      console.error(err);
    }
  });

  /* ---------- Métricas y tabla ---------- */
  function refreshMetrics() {
    if (!currentDataset) return;
    const s = currentDataset.stats;
    statTotal.textContent = s.total;
    statCritical.textContent = s.bySeverity['CRITICAL'] || 0;
    statHigh.textContent = s.bySeverity['HIGH'] || 0;
    statMedium.textContent = s.bySeverity['MEDIUM'] || 0;

    // Estadísticas de la pestaña de heurística
    if (ahTotal) ahTotal.textContent = s.total;
    if (ahCritical) ahCritical.textContent = s.bySeverity['CRITICAL'] || 0;
    if (ahHigh) ahHigh.textContent = s.bySeverity['HIGH'] || 0;
    if (ahMedium) ahMedium.textContent = s.bySeverity['MEDIUM'] || 0;
  }

  function renderLogTable() {
    if (!currentDataset) return;
    const search = searchFilter.value.toLowerCase();
    const sevFilter = severityFilter.value;
    const chartSev = ChartRenderer ? ChartRenderer.getSelectedSeverity() : null;

    const filtered = workingEvents.filter((evt) => {
      const srcIp = evt.sourceIp ? String(evt.sourceIp) : '';
      const cat = evt.category ? String(evt.category) : '';
      const act = evt.action ? String(evt.action) : '';
      const matchesText = srcIp.toLowerCase().includes(search) ||
        cat.toLowerCase().includes(search) ||
        act.toLowerCase().includes(search);
      const matchesSev = sevFilter === 'ALL' || evt.severity === sevFilter;
      const matchesChartSev = sevFilter === 'ALL' ? true : (!chartSev || evt.severity === chartSev);
      return matchesText && matchesSev && matchesChartSev;
    });

    // Ordenamiento
    if (tableSort.column) {
      const dir = tableSort.direction === 'asc' ? 1 : -1;
      filtered.sort((a, b) => {
        let va = a[tableSort.column];
        let vb = b[tableSort.column];
        if (va == null) va = '';
        if (vb == null) vb = '';
        va = String(va).toLowerCase();
        vb = String(vb).toLowerCase();
        if (va < vb) return -1 * dir;
        if (va > vb) return 1 * dir;
        return 0;
      });
    }

    // Encabezados de tabla clickeables
    const sortIndicator = (col) => {
      if (tableSort.column !== col) return '';
      return tableSort.direction === 'asc' ? ' ▲' : ' ▼';
    };

    logTableBody.innerHTML = filtered.map((evt) => `
      <tr>
        <td>${escapeHtml(formatDateTime(evt.epoch))}</td>
        <td>${escapeHtml(evt.sourceIp || '-')}</td>
        <td>${escapeHtml(evt.destinationIp || '-')}</td>
        <td>${escapeHtml(evt.category || 'General')}</td>
        <td class="severity-cell"><span class="sev-badge sev-${evt.severity ? evt.severity.toLowerCase() : 'info'}">${escapeHtml(evt.severity || 'INFO')}</span></td>
        <td class="action-cell">${escapeHtml(evt.action || '-')}</td>
        <td class="detail-cell">${escapeHtml(evt.description || '-')}</td>
      </tr>
    `).join('');
  }

  searchFilter.addEventListener('input', renderLogTable);
  severityFilter.addEventListener('change', () => {
    if (severityFilter.value === 'ALL') {
      ChartRenderer.setSelectedSeverity(null);
    }
    renderLogTable();
  });

  // Ordenamiento de tabla por encabezados clickeables
  const sortColumns = ['epoch', 'sourceIp', 'destinationIp', 'category', 'severity', 'action'];
  sortColumns.forEach((col) => {
    const th = document.querySelector(`th[data-sort="${col}"]`);
    if (th) {
      th.addEventListener('click', () => {
        if (tableSort.column === col) {
          tableSort.direction = tableSort.direction === 'asc' ? 'desc' : 'asc';
        } else {
          tableSort.column = col;
          tableSort.direction = 'asc';
        }
        renderLogTable();
      });
      // Estilo de cursor para indicar que es clickeable
      th.style.cursor = 'pointer';
      th.title = 'Haz clic para ordenar';
    }
  });

  // Botón de actualizar en la pestaña de heurística
  const btnRefreshAnalysis = document.getElementById('btn-refresh-analysis');
  if (btnRefreshAnalysis) {
    btnRefreshAnalysis.addEventListener('click', () => {
      renderLogTable();
      refreshCharts();
    });
  }

  /* ---------- Operaciones de limpieza eliminadas (pestaña removida) ---------- */



  /* ---------- Informes individuales ---------- */
  function renderIncidentSelector() {
    if (!currentDataset) return;
    incidentSelect.innerHTML = currentDataset.incidents.map((inc) =>
      `<option value="${inc.incidentId}">${inc.incidentId} · ${escapeHtml(inc.title)} (${inc.severity})</option>`
    ).join('');
  }

  viewIncidentBtn.addEventListener('click', () => {
    if (!currentDataset) return;
    const id = incidentSelect.value;
    const inc = currentDataset.incidents.find((i) => i.incidentId === id);
    if (!inc) return;

    incidentDetail.innerHTML = `
      <div class="incident-card-header">
        <h2>${escapeHtml(inc.incidentId)} · ${escapeHtml(inc.title)}</h2>
        <p>Expediente técnico de incidente de seguridad SOC Nivel 2</p>
      </div>
      <div class="incident-card-body">
        <div class="incident-metrics">
          <div class="incident-metric"><span class="label">Severidad</span><span class="value" style="color:${severityColor(inc.severity)}">${escapeHtml(inc.severity)}</span></div>
          <div class="incident-metric"><span class="label">Eventos</span><span class="value">${inc.events.length}</span></div>
          <div class="incident-metric"><span class="label">Alertas</span><span class="value">${inc.alerts.length}</span></div>
          <div class="incident-metric"><span class="label">Equipos</span><span class="value">${inc.hosts.length}</span></div>
          <div class="incident-metric"><span class="label">Cuentas</span><span class="value">${inc.users.length}</span></div>
          <div class="incident-metric"><span class="label">IPs Externas</span><span class="value">${inc.externalIps.length}</span></div>
        </div>

        <div class="incident-section">
          <h3>Justificación Técnica</h3>
          <div class="incident-justification">
            <span class="label">Análisis del analista SOC</span>
            <span class="text">${escapeHtml(inc.justification)}</span>
          </div>
        </div>

        <div class="incident-section">
          <h3>Ventana Temporal</h3>
          <div class="incident-detail-grid">
            <div class="incident-detail-item"><span class="label">Inicio</span><span class="value">${formatDateTime(inc.startTime)}</span></div>
            <div class="incident-detail-item"><span class="label">Fin</span><span class="value">${formatDateTime(inc.endTime)}</span></div>
            <div class="incident-detail-item"><span class="label">Duración</span><span class="value">${Math.round((inc.endTime - inc.startTime) / 60000)} min</span></div>
            <div class="incident-detail-item"><span class="label">Estado</span><span class="value">Correlacionado</span></div>
          </div>
        </div>

        <div class="incident-section">
          <h3>Activos y Cuentas Afectadas</h3>
          <div class="incident-detail-grid">
            <div class="incident-detail-item"><span class="label">Equipos</span><span class="value">${escapeHtml(inc.hosts.join(', '))}</span></div>
            <div class="incident-detail-item"><span class="label">Cuentas</span><span class="value">${escapeHtml(inc.users.join(', ') || '-')}</span></div>
            <div class="incident-detail-item"><span class="label">IPs Externas</span><span class="value">${escapeHtml(inc.externalIps.join(', ') || 'ninguna')}</span></div>
            <div class="incident-detail-item"><span class="label">Métricas MITRE</span><span class="value">${inc.mitre.length}</span></div>
          </div>
        </div>

        <div class="incident-section">
          <h3>Técnicas MITRE ATT&CK</h3>
          <div class="mitre-tags">
            ${inc.mitre.map((m) => `<span class="mitre-tag">${escapeHtml(m)}</span>`).join('') || '<span style="color:#64748b">Sin técnicas identificadas</span>'}
          </div>
        </div>

        <div class="incident-section">
          <h3>Impacto Organizacional</h3>
          <ul style="margin:0;padding-left:1rem;color:#334155;">
            ${inc.impact.map((x) => `<li>${escapeHtml(x)}</li>`).join('') || '<li>Sin impacto registrado</li>'}
          </ul>
        </div>

        <div class="incident-section">
          <h3>Plan de Acción</h3>
          <div class="plan-tabs">
            <button class="plan-tab active" onclick="switchPlan(this, 'investigar')">🔍 Investigar</button>
            <button class="plan-tab" onclick="switchPlan(this, 'contener')">🛡️ Contener</button>
            <button class="plan-tab" onclick="switchPlan(this, 'remediar')">✅ Remediar</button>
          </div>
          <div class="plan-content active" id="plan-investigar">
            <div class="plan-column investigar">
              <h4>Investigar</h4>
              <ul>${inc.plan.inv.map((x) => `<li>${escapeHtml(x)}</li>`).join('') || '<li>Sin acciones definidas</li>'}</ul>
            </div>
          </div>
          <div class="plan-content" id="plan-contener">
            <div class="plan-column contener">
              <h4>Contener</h4>
              <ul>${inc.plan.con.map((x) => `<li>${escapeHtml(x)}</li>`).join('') || '<li>Sin acciones definidas</li>'}</ul>
            </div>
          </div>
          <div class="plan-content" id="plan-remediar">
            <div class="plan-column remediar">
              <h4>Remediar</h4>
              <ul>${inc.plan.rem.map((x) => `<li>${escapeHtml(x)}</li>`).join('') || '<li>Sin acciones definidas</li>'}</ul>
            </div>
          </div>
        </div>

        ${inc.related.length ? `
        <div class="incident-section">
          <h3>Relación con Otros Incidentes</h3>
          <div class="incident-related">
            <strong>Relacionado:</strong> ${inc.related.map((r) => `${r.id} (${escapeHtml(r.why)})`).join('; ')}
          </div>
        </div>
        ` : ''}
      </div>
    `;
  });

  /* ---------- Asistente de IA (Google Gemini real) ---------- */
  btnCheckGemini.addEventListener('click', async () => {
    const key = geminiKeyInput.value.trim();
    if (!key) {
      geminiStatus.textContent = 'Introduce tu clave API de Gemini primero.';
      geminiStatus.className = 'ai-status err';
      geminiStatus.hidden = false;
      geminiConnected = false;
      return;
    }
    btnCheckGemini.disabled = true;
    geminiStatus.textContent = 'Verificando conexión con Gemini…';
    geminiStatus.className = 'ai-status wait';
    geminiStatus.hidden = false;
    try {
      const result = await AIAssistant.checkConnection(key);
      geminiStatus.textContent = result.message;
      geminiStatus.className = result.ok ? 'ai-status ok' : 'ai-status err';
      geminiConnected = result.ok;
      if (result.ok) {
        geminiApiKey = key;
        geminiModel = geminiModelSelect.value;
        btnCheckGemini.textContent = 'Conexión OK';
        btnCheckGemini.classList.add('btn-success');
      } else {
        geminiConnected = false;
      }
    } catch (err) {
      geminiStatus.textContent = 'Error: ' + escapeHtml(err.message);
      geminiStatus.className = 'ai-status err';
      geminiConnected = false;
    } finally {
      btnCheckGemini.disabled = false;
    }
  });

  geminiKeyInput.addEventListener('input', () => {
    geminiConnected = false;
    btnCheckGemini.textContent = 'Chequear conexión';
    btnCheckGemini.classList.remove('btn-success');
    geminiStatus.hidden = true;
  });

  aiRunBtn.addEventListener('click', async () => {
    if (!currentDataset) {
      aiResult.innerHTML = '<p style="color:#ef4444">No hay datos cargados para analizar.</p>';
      return;
    }
    if (!geminiConnected || !geminiApiKey) {
      aiResult.innerHTML = '<p style="color:#ef4444">Primero introduce tu clave API de Gemini y haz clic en "Chequear conexión".</p>';
      return;
    }
    aiResult.innerHTML = '<p style="color:#2563eb">Consultando a Gemini… esto puede tardar unos segundos.</p>';

    try {
      const resultado = await AIAssistant.analyze(geminiApiKey, geminiModel, currentDataset.stats, currentDataset.events, currentDataset.incidents);
      aiResult.innerHTML = resultado;
    } catch (err) {
      aiResult.innerHTML = '<p style="color:#ef4444">Error de la API: ' + escapeHtml(err.message) + '</p>';
    }
  });

  /* ---------- Descarga de PDF ---------- */
  const buildMetadata = () => ({
    client: 'Cliente corporativo',
    analyst: 'Analista SOC',
    company: 'Consultora de Ciberseguridad',
    ref: 'SOC-' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-01',
    file: fileInput.files[0] ? fileInput.files[0].name : 'datos_cargados'
  });

  const downloadReport = async (reportType) => {
    if (!currentDataset) { alert('No hay datos para generar el informe.'); return; }
    let blocks;
    try {
      if (reportType === 'ejecutivo') {
        blocks = ReportBuilder.buildExecutive(currentDataset, buildMetadata());
      } else if (reportType === 'tecnico') {
        blocks = ReportBuilder.buildTechnical(currentDataset, buildMetadata());
      } else {
        blocks = ReportBuilder.buildCombined(currentDataset, buildMetadata());
      }
    } catch (err) {
      alert('Error generando el informe: ' + err.message);
      console.error('PDF generation error:', err);
      return;
    }

    try {
      const pdfBytes = PDFGenerator.render(blocks);
      const blob = new Blob([pdfBytes], { type: 'application/pdf' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'Informe_SOC_' + reportType + '_' + (new Date().toISOString().slice(0, 10)) + '.pdf';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Error descargando el PDF: ' + err.message);
      console.error('PDF download error:', err);
    }
  };

  downloadPdfBtn.addEventListener('click', () => {
    const reportType = prompt('Selecciona tipo de informe:\n1 = Ejecutivo (para dirección)\n2 = Técnico (expediente SOC L2/L3)\n3 = Ambos (ejecutivo + técnico)', '3');
    if (reportType === '1') downloadReport('ejecutivo');
    else if (reportType === '2') downloadReport('tecnico');
    else if (reportType === '3' || reportType === null) downloadReport('combined');
  });

  // Botones de la pestaña Descargas
  if (downloadExecBtn) {
    downloadExecBtn.addEventListener('click', () => downloadReport('ejecutivo'));
  }
  if (downloadTechBtn) {
    downloadTechBtn.addEventListener('click', () => downloadReport('tecnico'));
  }
  if (downloadCombinedBtn) {
    downloadCombinedBtn.addEventListener('click', () => downloadReport('combined'));
  }


  /* ---------- Envío de correo ---------- */
  emailForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!currentDataset) { showEmailFeedback('No hay datos cargados para enviar.', 'err'); return; }

    const activePanel = document.querySelector('.tab-pane.active');
    let blocks;
    if (activePanel.id === 'view-incidents') {
      blocks = ReportBuilder.buildTechnical(currentDataset, {
        client: 'Cliente corporativo',
        analyst: 'Analista SOC',
        company: 'Consultora de Ciberseguridad',
        ref: emailSubject.value || 'SOC-REF',
        file: fileInput.files[0] ? fileInput.files[0].name : 'datos_cargados'
      });
    } else {
      blocks = ReportBuilder.buildExecutive(currentDataset, {
        client: 'Cliente corporativo',
        analyst: 'Analista SOC',
        company: 'Consultora de Ciberseguridad',
        ref: emailSubject.value || 'SOC-REF',
        file: fileInput.files[0] ? fileInput.files[0].name : 'datos_cargados'
      });
    }

    try {
      const pdfBytes = PDFGenerator.render(blocks);
      const blob = new Blob([pdfBytes], { type: 'application/pdf' });

      await EmailDispatcher.send(emailTo.value, emailSubject.value, emailBody.value || 'Informe adjunto', blob);
      showEmailFeedback('Correo despachado exitosamente a ' + escapeHtml(emailTo.value), 'ok');
      emailForm.reset();
    } catch (err) {
      showEmailFeedback('Error al despachar: ' + escapeHtml(err.message), 'err');
    }
  });

  function showEmailFeedback(message, type) {
    emailFeedback.textContent = message;
    emailFeedback.className = 'status-msg ' + (type === 'ok' ? 'status-ok' : 'status-err');
    emailFeedback.hidden = false;
    setTimeout(() => { emailFeedback.hidden = true; }, 5000);
  }

  /* ---------- Gráficos ---------- */
  function refreshCharts() {
    console.log('refreshCharts llamado, currentDataset:', !!currentDataset);
    if (!currentDataset) {
      // Limpiar gráficos cuando no hay datos
      const contSev = document.getElementById('chart-severity');
      const contCat = document.getElementById('chart-category');
      if (contSev) contSev.innerHTML = '<p style="color:#64748b;text-align:center;padding:1rem">Sin datos cargados</p>';
      if (contCat) contCat.innerHTML = '<p style="color:#64748b;text-align:center;padding:1rem">Sin datos cargados</p>';
      return;
    }
    const s = currentDataset.stats;
    const sevCounts = s.bySeverity || {};
    const catCounts = s.byCategory || {};
    const catSev = s.byCategorySeverity || {};
    console.log('Stats recibidos:', s, '| bySeverity:', sevCounts, '| byCategory:', catCounts, '| byCategorySeverity:', catSev);

    // Conectar el gráfico de anillo con el filtrado de la tabla
    ChartRenderer.setSelectedSeverity(null);
    ChartRenderer.onSeverityChange = (sev) => {
      ChartRenderer.setSelectedSeverity(sev);
      severityFilter.value = sev || 'ALL';
      renderLogTable();
      refreshMetrics();
    };

    ChartRenderer.drawSeverity('chart-severity', sevCounts, (sev) => {
      ChartRenderer.setSelectedSeverity(sev);
      severityFilter.value = sev || 'ALL';
      renderLogTable();
      refreshMetrics();
    });
    ChartRenderer.drawCategory('chart-category', catCounts, catSev);
    console.log('Gráficos renderizados');
  }

  // Exponer para pruebas automatizadas
  window.SOCController = { refreshMetrics, renderLogTable, renderIncidentSelector, refreshCharts };

  /* ---------- Funciones auxiliares de expedientes ---------- */
  function severityColor(severity) {
    switch (String(severity).toUpperCase()) {
      case 'CRITICAL': return '#dc2626';
      case 'HIGH': return '#ea580c';
      case 'MEDIUM': return '#eab308';
      default: return '#2563eb';
    }
  }

  function switchPlan(btn, plan) {
    document.querySelectorAll('.plan-tab').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.plan-content').forEach((c) => c.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('plan-' + plan).classList.add('active');
  }
})();
