/**
 * Constructor de bloques de informe de seguridad SOC Nivel 3.
 * Genera informes Ejecutivo y Técnico separados, listos para producción.
 * Expone: window.ReportBuilder
 */
(function (global) {
  'use strict';

  const formatTime = (ts) => new Date(ts).toISOString().slice(11, 19);
  const formatDateTime = (ts) => new Date(ts).toISOString().slice(0, 19).replace('T', ' ');
  const uniqueValues = (arr) => [...new Set(arr.filter(Boolean))];
  const severityOrder = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const severityRank = (level) => severityOrder.indexOf(String(level).toUpperCase()) || 0;

  /* ---------- Utilidades de extracción de datos ---------- */
  function countBySeverity(incidents) {
    const c = {};
    ['CRITICAL','HIGH','MEDIUM','INFO'].forEach((s) => c[s] = 0);
    incidents.forEach((i) => { const s = i.severity || 'INFO'; c[s] = (c[s] || 0) + 1; });
    return c;
  }

  function evidenceRows(incident) {
    const rows = [];
    incident.alerts.forEach((alert) => {
      const events = alert.events;
      const sample = events.length > 6 ? events.slice(0, 3).concat([null], events.slice(-1)) : events;
      sample.forEach((evt) => {
        if (!evt) { rows.push(['…', '', '', '', '', '', `(+${events.length - 4} eventos similares de la misma alerta)`]); return; }
        if (rows.some((r) => r[0] === evt.recordId)) return;
        rows.push([evt.recordId, evt.timestampRaw.slice(11), evt.host, evt.eventId, evt.shortUser || '-', evt.sourceIp || '-', (evt.description + (evt.command ? ' | ' + evt.command : '')).slice(0, 170)]);
      });
    });
    return rows;
  }

  function compileIndicators(dataset) {
    const indicators = [];
    const ipRoles = {};
    dataset.incidents.forEach((inc) => inc.externalIps.forEach((ip) => { (ipRoles[ip] = ipRoles[ip] || []).push(inc.incidentId); }));
    for (const [ip, ids] of Object.entries(ipRoles)) {
      const inc = dataset.incidents.find((i) => i.id === ids[0]);
      const events = inc && inc.events ? inc.events : [];
      const isDestination = events.some((e) => e.destinationIp.includes(ip));
      indicators.push(['IP', ip, isDestination ? 'Destino de exfiltración / C2' : 'Origen de ataque', uniqueValues(ids).join(', ')]);
    }
    dataset.incidents.filter((i) => i.alerts.some((a) => a.compromised)).forEach((inc) => {
      inc.alerts.filter((a) => a.compromised).forEach((a) => a.users.forEach((u) => {
        if (!indicators.some((r) => r[1] === u)) indicators.push(['Cuenta', u, 'Cuenta comprometida / usada por el atacante', inc.incidentId]);
      }));
    });
    dataset.incidents.forEach((inc) => {
      const events = inc.events || [];
      events.forEach((e) => {
        const matches = (e.command + ' ' + e.description).match(/[A-Z]:\\[^\s;|]+\.(zip|7z|exe|ps1|rar|dll)|\/[\w/]+\.(aspx|php|jsp)/gi) || [];
        matches.forEach((f) => { if (!indicators.some((r) => r[1] === f)) indicators.push(['Archivo', f, 'Artefacto del atacante', inc.incidentId]); });
        const taskMatch = (e.command.match(/TaskName=([^;]+)|ServiceName=([^;]+)/) || []);
        if (taskMatch[1] || taskMatch[2]) { const value = (taskMatch[1] || taskMatch[2]).trim(); if (!indicators.some((r) => r[1] === value)) indicators.push([taskMatch[1] ? 'Tarea' : 'Servicio', value, 'Persistencia', inc.incidentId]); }
      });
    });
    return indicators;
  }

  function compileMitreMap(incidents) {
    const map = {};
    incidents.forEach((inc) => {
      inc.alerts.forEach((a) => {
        (a.mitre || []).forEach((m) => {
          const [tid, name] = m;
          if (!map[tid]) map[tid] = { name, count: 0, incidents: [] };
          map[tid].count++;
          map[tid].incidents.push(inc.incidentId);
        });
      });
    });
    return map;
  }

  /* ---------- INFORME EJECUTIVO (Dirección / Negocio) ---------- */
  function buildExecutiveReport(dataset, metadata) {
    const blocks = [];
    const { stats, incidents, alerts } = dataset;
    const c = countBySeverity(incidents);
    const criticals = incidents.filter((i) => i.severity === 'CRITICAL');
    const highs = incidents.filter((i) => i.severity === 'HIGH');
    const bytes = alerts.filter((a) => a.bytes).reduce((s, a) => s + a.bytes, 0);
    const compromised = uniqueValues(alerts.filter((a) => a.compromised).flatMap((a) => a.users)).filter((u) => u !== '-' && !/apppool/i.test(u));
    const externalIps = uniqueValues(alerts.flatMap((a) => a.ips || [])).filter((ip) => ip);

    // Valores por defecto seguros para metadata
    const m = metadata || {};
    const client = m.client || 'Cliente corporativo';
    const analyst = m.analyst || 'Analista SOC';
    const company = m.company || 'Consultora de Ciberseguridad';
    const ref = m.ref || 'SOC-' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-01';
    const file = m.file || 'datos_cargados';

    /* ---------- PORTADA ---------- */
    blocks.push({ type: 'cover', title: 'Informe Ejecutivo de Incidentes de Seguridad', subtitle: 'Resumen para la dirección y alta gerencia',
      keyValue: [
        [client, 'Cliente / Organización'],
        [analyst + ' · Analista SOC Nivel 2', 'Analista a cargo'],
        [company, 'Consultora / Proveedor'],
        [`${formatDateTime(stats.startTime)} – ${formatDateTime(stats.endTime)}`, 'Periodo analizado'],
        [file + ` (${stats.total} eventos)`, 'Archivo de registros analizado'],
        [new Date().toISOString().slice(0, 10), 'Fecha del informe'],
        ['CONFIDENCIAL – uso exclusivo del cliente y dirección', 'Clasificación']
      ] });

    /* ---------- 1. RESUMEN EJECUTIVO DE LA OPERACIÓN ---------- */
    blocks.push({ type: 'heading2', text: '1. Resumen Ejecutivo de la Operación' });
    blocks.push({ type: 'paragraph', text: `Se analizaron ${stats.total} eventos exportados del sistema SIEM de ${client}, correspondientes a ${stats.hosts} equipos y ${stats.users} cuentas de usuario, en el periodo comprendido entre ${formatDateTime(stats.startTime)} y ${formatDateTime(stats.endTime)}. El motor de detección marcó ${stats.flagged} eventos como sospechosos y los correlacionó en ${incidents.length} incidentes de seguridad.` });
    blocks.push({ type: 'paragraph', text: `Estado general: ${criticals.length > 0 ? 'SE DETECTARON INCIDENTES CRÍTICOS que requieren atención inmediata de la alta dirección.' : 'No se detectaron incidentes críticos, pero se identificaron hallazgos que requieren seguimiento.'} Se correlacionaron ${incidents.length} incidentes en total: ${c.CRITICAL} crítico(s), ${c.HIGH} alto(s), ${c.MEDIUM} medio(s) y ${c.INFO} informativo(s).` });

    /* ---------- 2. PANORAMA DE RIESGO Y CRITICIDAD ---------- */
    blocks.push({ type: 'heading2', text: '2. Panorama de Riesgo y Criticidad' });
    blocks.push({ type: 'table', header: ['Nivel de Criticidad', 'Cantidad de Incidentes', 'Porcentaje', 'Acción Requerida'], widths: [120, 120, 100, 260],
      rows: [
        ['Crítico', String(c.CRITICAL || 0), c.CRITICAL ? Math.round((c.CRITICAL / incidents.length) * 100) + '%' : '0%', 'Respuesta inmediata (< 1 hora). Notificación a dirección y CERT.'],
        ['Alto', String(c.HIGH || 0), c.HIGH ? Math.round((c.HIGH / incidents.length) * 100) + '%' : '0%', 'Respuesta en menos de 4 horas. Contención y análisis forense.'],
        ['Medio', String(c.MEDIUM || 0), c.MEDIUM ? Math.round((c.MEDIUM / incidents.length) * 100) + '%' : '0%', 'Verificación en la jornada laboral.'],
        ['Informativo / Higiene', String(c.INFO || 0), c.INFO ? Math.round((c.INFO / incidents.length) * 100) + '%' : '0%', 'Seguimiento planificado y auditoría.'],
        ['TOTAL', String(incidents.length), '100%', 'Revisión completa del panorama de amenazas.']
      ] });
    blocks.push({ type: 'severityBars', data: ['CRITICAL','HIGH','MEDIUM','INFO'].map((s) => [s, c[s] || 0]) });
    blocks.push({ type: 'paragraph', text: `Hechos de mayor gravedad: ${criticals.length ? criticals.map((i) => `${i.incidentId}: ${i.title}`).join('; ') + '.' : 'No se identificaron incidentes críticos en el periodo analizado.'}` });
    if (compromised.length) blocks.push({ type: 'paragraph', text: `Se identificaron ${compromised.length} cuenta(s) con credenciales posiblemente comprometidas: ${compromised.join(', ')}.` });
    if (bytes) blocks.push({ type: 'paragraph', text: `Se detectó una salida aproximada de ${global.SIEMAnalyzer.formatBytes(bytes)} de información hacia servidores externos.` });

    /* ---------- 3. IMPACTO OPERATIVO Y SISTEMAS AFECTADOS ---------- */
    blocks.push({ type: 'heading2', text: '3. Impacto Operativo y Sistemas Afectados' });
    const allHosts = uniqueValues(incidents.flatMap((i) => i.hosts));
    const criticalHosts = uniqueValues(criticals.flatMap((i) => i.hosts));
    blocks.push({ type: 'paragraph', text: `Se vieron afectados un total de ${allHosts.length} equipo(s) en la organización. ${criticalHosts.length} equipo(s) están asociados directamente a incidentes críticos.` });
    blocks.push({ type: 'table', header: ['Sistema / Equipo', 'Riesgo Asociado', 'Incidentes Relacionados'], widths: [200, 200, 200],
      rows: criticals.map((i) => [i.hosts.join(', ') || 'No especificado', i.title, i.incidentId]) });
    if (externalIps.length) {
      blocks.push({ type: 'paragraph', text: `IPs externas identificadas como origen de ataque o destino de exfiltración: ${externalIps.join(', ')}.` });
    }

    /* ---------- 4. CONCLUSIONES ESTRATÉGICAS Y RECOMENDACIONES DE GOBERNANZA ---------- */
    blocks.push({ type: 'heading2', text: '4. Conclusiones Estratégicas y Recomendaciones de Gobernanza' });
    blocks.push({ type: 'paragraph', text: `Conclusión: ${criticals.length ? 'SÍ se confirmaron incidentes de seguridad con impacto potencial en la continuidad del negocio.' : 'No se confirmaron incidentes críticos, pero se identificaron áreas de mejora en la postura de seguridad.'}` });
    blocks.push({ type: 'list', items: [
      'Implementar Autenticación Multifactor (MFA) obligatoria para todos los accesos remotos y cuentas privilegiadas.',
      'Establecer políticas de bloqueo de cuenta y detección de password spraying en el SIEM con respuesta automática (SOAR).',
      'Adoptar un modelo de gobernanza de cuentas privilegiadas (cuentas admin nominativas, LAPS, modelo por niveles).',
      'Reforzar la protección de endpoints con EDR, Script Block Logging y Constrained Language Mode en PowerShell.',
      'Implementar copias de seguridad inmutables y fuera de línea (regla 3-2-1) con pruebas de restauración periódicas.',
      'Desplegar DLP en el perímetro y monitoreo de volumen saliente para prevenir exfiltración de datos.',
      'Segmentar la red: restringir SMB/RDP entre servidores y acceso a sistemas críticos (finanzas, RRHH, contabilidad).',
      'Establecer procedimiento de notificación de brechas de datos ante autoridades de protección (GDPR 72 horas) y planes de respuesta a incidentes documentados.'
    ] });
    blocks.push({ type: 'paragraph', text: `Informe generado por NODO SOC el ${new Date().toISOString().slice(0, 10)}. Este documento debe ser revisado por la alta dirección antes de ejecutar acciones de contención o remediación.`, muted: true });
    return blocks;
  }

  /* ---------- INFORME TÉCNICO / EXPEDIENTE DE INCIDENTES (SOC L2/L3, CERT, Forense) ---------- */
  function buildTechnicalReport(dataset, metadata) {
    const blocks = [];
    const { stats, incidents, alerts } = dataset;
    const c = countBySeverity(incidents);
    const mitreMap = compileMitreMap(incidents);

    // Valores por defecto seguros para metadata
    const m = metadata || {};
    const client = m.client || 'Cliente corporativo';
    const analyst = m.analyst || 'Analista SOC';
    const company = m.company || 'Consultora de Ciberseguridad';
    const ref = m.ref || 'SOC-' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-01';
    const file = m.file || 'datos_cargados';

    /* ---------- PORTADA ---------- */
    blocks.push({ type: 'cover', title: 'Informe Técnico – Expediente de Incidentes SOC', subtitle: 'Análisis forense y técnico para SOC L2/L3, CERT y equipos de ingeniería',
      keyValue: [
        [client, 'Cliente / Organización'],
        [analyst + ' · Analista SOC Nivel 3', 'Analista a cargo'],
        [company, 'Consultora / Proveedor'],
        [`${formatDateTime(stats.startTime)} – ${formatDateTime(stats.endTime)}`, 'Periodo analizado'],
        [file + ` (${stats.total} eventos)`, 'Archivo de registros analizado'],
        [new Date().toISOString().slice(0, 10), 'Fecha del informe'],
        ['CONFIDENCIAL – uso exclusivo del equipo de respuesta a incidentes', 'Clasificación']
      ] });

    /* ---------- 1. TRAZABILIDAD Y CRONOLOGÍA FORENSE ---------- */
    blocks.push({ type: 'heading2', text: '1. Trazabilidad y Cronología Forense' });
    blocks.push({ type: 'paragraph', text: `Se reconstruyó la cadena de ataque a partir de ${stats.total} eventos del SIEM, correlacionando ${alerts.length} alertas en ${incidents.length} incidentes. La siguiente tabla presenta la línea de tiempo detallada con marcas de tiempo, IDs de evento y comandos ejecutados.` });
    const timeline = alerts.filter((a) => incidents.some((inc) => inc.alerts.includes(a) && inc.severity !== 'INFO')).sort((a, b) => a.startTime - b.startTime);
    blocks.push({ type: 'table', header: ['Marca de Tiempo', 'ID Evento', 'Severidad', 'Evento Detectado', 'Host / Usuario', 'IP Origen'], widths: [130, 80, 80, 200, 140, 100],
      rows: timeline.map((a) => {
        const inc = incidents.find((x) => x.alerts.includes(a));
        const ev = (a.events && a.events[0]) || {};
        return [formatTime(a.startTime), a.ruleId || '-', a.severity || '-', a.title, `${ev.host || '-'} / ${ev.shortUser || '-'}`, ev.sourceIp || '-'];
      }) });

    /* ---------- 2. DESGLOSE DE INCIDENTES CORRELACIONADOS ---------- */
    blocks.push({ type: 'heading2', text: '2. Desglose de Incidentes Correlacionados' });
    blocks.push({ type: 'table', header: ['ID Incidente', 'Título', 'Criticidad', 'Ventana de Tiempo', 'Categoría Principal', 'Técnicas MITRE'], widths: [70, 220, 80, 130, 150, 150],
      rows: incidents.map((i) => [i.incidentId, i.title, i.severity, `${formatTime(i.startTime)} – ${formatTime(i.endTime)}`, i.category || '-', (i.mitre || []).map((m) => m[0]).join(', ') || '-']) });
    blocks.push({ type: 'paragraph', text: `Cada incidente agrupa alertas que comparten IP externa, cuenta de usuario o ventana temporal de 120 minutos. Se identificaron ${incidents.length} incidentes correlacionados.` });

    /* ---------- 3. MATRIZ DE INDICADORES DE COMPROMISO (IoCs) ---------- */
    blocks.push({ type: 'heading2', text: '3. Matriz de Indicadores de Compromiso (IoCs)' });
    const iocs = compileIndicators(dataset);
    blocks.push({ type: 'table', header: ['Tipo', 'Indicador', 'Descripción', 'Incidente(s)'], widths: [80, 220, 220, 80],
      rows: iocs.length ? iocs : [['-', 'No se identificaron IoCs', '-', '-']] });

    /* ---------- 4. MAPEO TÁCTICO MITRE ATT&CK ---------- */
    blocks.push({ type: 'heading2', text: '4. Mapeo Táctico MITRE ATT&CK' });
    const mitreEntries = Object.entries(mitreMap).sort((a, b) => b[1].count - a[1].count);
    blocks.push({ type: 'table', header: ['Técnica MITRE', 'Nombre', 'Frecuencia', 'Incidente(s)'], widths: [100, 220, 80, 200],
      rows: mitreEntries.map(([tid, info]) => [tid, info.name, String(info.count), info.incidents.join(', ')]) });
    if (mitreEntries.length === 0) {
      blocks.push({ type: 'paragraph', text: 'No se identificaron técnicas MITRE ATT&CK asociadas a los eventos analizados.' });
    }

    /* ---------- 5. PLAN DE MITIGACIÓN Y CONTENCIÓN APLICADA ---------- */
    blocks.push({ type: 'heading2', text: '5. Plan de Mitigación y Contención Aplicada' });
    blocks.push({ type: 'list', items: [
      'Bloquear en el perímetro del firewall las direcciones IP externas identificadas como origen de ataque o destino de exfiltración (IoCs).',
      'Aislar los endpoints afectados mediante EDR y desconectar de la red los equipos comprometidos.',
      'Revocar credenciales de cuentas involucradas y restablecer contraseñas de cuentas privilegiadas.',
      'Eliminar mecanismos de persistencia no autorizados (tareas programadas, servicios imitando Windows Update).',
      'Preservar evidencias forenses: imágenes de disco, registros de eventos y memoria volátil para análisis posterior.',
      'Evaluar notificación de la brecha a autoridades de protección de datos (GDPR: plazo de 72 horas) y a partes afectadas.',
      'Implementar monitoreo mejorado en los vectores de ataque identificados para detección temprana de reincidencia.'
    ] });
    blocks.push({ type: 'paragraph', text: `Informe generado por NODO SOC el ${new Date().toISOString().slice(0, 10)}. Los hallazgos técnicos deben ser validados por el analista forense antes de ejecutar acciones de contención o remediación.`, muted: true });
    return blocks;
  }

  /* ---------- INFORME COMBINADO (Ejecutivo + Técnico) ---------- */
  function buildCombinedReport(dataset, metadata, aiText) {
    const blocks = [];
    const { stats } = dataset;

    // Valores por defecto seguros para metadata
    const m = metadata || {};
    const client = m.client || 'Cliente corporativo';
    const analyst = m.analyst || 'Analista SOC';
    const company = m.company || 'Consultora de Ciberseguridad';
    const ref = m.ref || 'SOC-' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-01';
    const file = m.file || 'datos_cargados';

    blocks.push({ type: 'cover', title: 'Informe de Seguridad SOC – Ejecutivo y Técnico', subtitle: 'Análisis completo de logs exportados del SIEM',
      keyValue: [
        [client, 'Cliente / Organización'],
        [analyst + ' · Analista SOC Nivel 2/3', 'Analista a cargo'],
        [company, 'Consultora / Proveedor'],
        [`${formatDateTime(stats.startTime)} – ${formatDateTime(stats.endTime)}`, 'Periodo analizado'],
        [file + ` (${stats.total} eventos)`, 'Archivo de registros analizado'],
        [new Date().toISOString().slice(0, 10), 'Fecha del informe'],
        ['CONFIDENCIAL – uso exclusivo del cliente y equipo de respuesta', 'Clasificación']
      ] });

    blocks.push({ type: 'heading2', text: 'PARTE I – INFORME EJECUTIVO' });
    const execBlocks = buildExecutiveReport(dataset, metadata);
    execBlocks.forEach((b) => blocks.push(b));

    blocks.push({ type: 'pageBreak' });

    blocks.push({ type: 'heading2', text: 'PARTE II – INFORME TÉCNICO / EXPEDIENTE DE INCIDENTES' });
    const techBlocks = buildTechnicalReport(dataset, metadata);
    techBlocks.forEach((b) => blocks.push(b));

    return blocks;
  }

  const escapeHtml = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  function toHtml(blocks) {
    return blocks.map((block) => {
      switch (block.type) {
        case 'cover': return `<h1>${escapeHtml(block.title)}</h1><p class="meta">${escapeHtml(block.subtitle)}</p><table>${block.keyValue.filter((kv) => kv[1]).map((kv) => `<tr><td style="width:150px"><b>${escapeHtml(kv[0])}</b></td><td>${escapeHtml(kv[1])}</td></tr>`).join('')}</table>`;
        case 'heading2': return `<h2>${escapeHtml(block.text)}</h2>`;
        case 'heading3': return `<h3>${block.severity ? `<span class="severity-badge ${severityClass(block.severity)}">${block.severity}</span> ` : ''}${escapeHtml(block.text)}</h3>`;
        case 'heading4': return `<p><b>${escapeHtml(block.text)}</b></p>`;
        case 'paragraph': return `<p${block.muted ? ' class="meta"' : ''}>${escapeHtml(block.text)}</p>`;
        case 'box': return `<div class="box">${escapeHtml(block.text)}</div>`;
        case 'list': return `<ul>${block.items.map((i) => `<li>${escapeHtml(i)}</li>`).join('')}</ul>`;
        case 'keyValue': return `<table>${block.keyValue.map((kv) => `<tr><td style="width:150px"><b>${escapeHtml(kv[0])}</b></td><td>${escapeHtml(kv[1])}</td></tr>`).join('')}</table>`;
        case 'steps': return `<table>${block.items.map((s) => `<tr><td class="mono" style="width:70px">${escapeHtml(s[0])}</td><td><b>${escapeHtml(s[1])}</b><br>${escapeHtml(s[2])}</td></tr>`).join('')}</table>`;
        case 'table': return `<table><tr>${block.header.map((h) => `<th>${escapeHtml(h)}</th>`).join('')}</tr>${block.rows.map((r) => `<tr>${r.map((c, j) => `<td${block.small && j !== 6 ? ' class="mono"' : ''}>${['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(c) ? `<span class="severity-badge ${severityClass(c)}">${c}</span>` : escapeHtml(c)}</td>`).join('')}</tr>`).join('')}</table>`;
        case 'actionPlan': return `<table><tr><th>Investigar</th><th>Contener</th><th>Remediar</th></tr><tr>${['investigate', 'contain', 'remediate'].map((k) => `<td><ul style="margin:0;padding-left:16px">${block[k].map((i) => `<li>${escapeHtml(i)}</li>`).join('')}</ul></td>`).join('')}</tr></table>`;
        case 'severityBars': return `<table><tr>${block.data.map((d) => `<td style="text-align:center"><span class="severity-badge ${severityClass(d[0])}">${d[0]}</span><div style="font-size:24px;font-weight:700">${d[1]}</div></td>`).join('')}</tr></table>`;
        case 'pageBreak': return '<hr style="border:0;border-top:1px dashed #d5dbe6;margin:24px 0">';
        default: return '';
      }
    }).join('\n');
  }

  function severityClass(severity) {
    switch (String(severity).toUpperCase()) {
      case 'CRITICAL': return 'sev-critical';
      case 'HIGH': return 'sev-high';
      case 'MEDIUM': return 'sev-medium';
      default: return 'sev-info';
    }
  }

  function generateAiPrompt(dataset, metadata) {
    const summary = dataset.incidents.map((i) => ({
      id: i.incidentId, title: i.title, severity: i.severity, window: `${formatDateTime(i.startTime)} - ${formatTime(i.endTime)}`, hosts: i.hosts, users: i.users, externalIps: i.externalIps,
      alerts: i.alerts.map((a) => `${formatTime(a.startTime)} ${a.title}: ${a.detail}`), mitre: i.mitre
    }));
    return `Eres un analista SOC Nivel 2 senior. Redacta en español, en tono profesional para la dirección del cliente "${metadata.client}", el análisis de esta investigación. Responde en texto plano (sin markdown) con párrafos separados por una línea en blanco:\n1) Un resumen ejecutivo de máximo 180 palabras: si hubo uno o varios incidentes, su gravedad y el riesgo para el negocio.\n2) Una hipótesis de la cadena de ataque (cómo podrían relacionarse los incidentes entre sí), señalando qué es hecho y qué es suposición.\n3) Las 5 acciones prioritarias para las próximas 24 horas.\nNo inventes datos que no estén abajo.\n\nPeriodo: ${formatDateTime(dataset.stats.startTime)} a ${formatDateTime(dataset.stats.endTime)}. Eventos: ${dataset.stats.total}.\nIncidentes detectados (JSON):\n${JSON.stringify(summary, null, 1)}`;
  }

  global.ReportBuilder = { buildExecutive: buildExecutiveReport, buildTechnical: buildTechnicalReport, buildCombined: buildCombinedReport, toHtml: toHtml, generateAiPrompt: generateAiPrompt };
})(window);
