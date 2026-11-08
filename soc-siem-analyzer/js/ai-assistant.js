/**
 * Asistente de inteligencia artificial para el SOC.
 * Integración real con Google Gemini usando clave API del usuario.
 * Expone: window.AIAssistant
 */
(function (global) {
  'use strict';

  const API_BASE = 'https://generativelanguage.googleapis.com/v1beta';

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text ?? '';
    return div.innerHTML;
  }

  function buildSiemPrompt(stats, events, incidents) {
    const criticals = incidents.filter((i) => i.severity === 'CRITICAL');
    const highs = incidents.filter((i) => i.severity === 'HIGH');
    const compromised = [];
    const externalIps = [];

    incidents.forEach((inc) => {
      inc.alerts.forEach((alert) => {
        if (alert.compromised) alert.users.forEach((u) => { if (u && u !== '-') compromised.push(u); });
        if (alert.external) alert.ips.forEach((ip) => { if (ip) externalIps.push(ip); });
      });
    });

    const uniqueAccounts = [...new Set(compromised)];
    const uniqueExternalIps = [...new Set(externalIps)];

    const incidentSummary = incidents.map((inc) => ({
      id: inc.incidentId,
      title: inc.title,
      severity: inc.severity,
      start: inc.startTime ? new Date(inc.startTime).toISOString() : '',
      end: inc.endTime ? new Date(inc.endTime).toISOString() : '',
      hosts: inc.hosts,
      accounts: inc.users,
      externalIps: inc.externalIps,
      mitre: inc.mitre,
      justification: inc.justification,
      alertsCount: inc.alerts.length,
      eventsCount: inc.events.length
    }));

    const alertSummary = incidents.flatMap((inc) => inc.alerts.map((a) => ({
      rule: a.ruleId,
      category: a.category,
      severity: a.severity,
      title: a.title,
      detail: a.detail,
      mitre: a.mitre,
      compromised: !!a.compromised,
      external: !!a.external,
      events: a.events.length
    })));

    return `Eres un analista de seguridad SOC Nivel 2 senior, especializado en SIEM, IDS y EDR. Tu tarea es analizar el siguiente archivo de logs de seguridad exportado de un sistema SIEM y generar un informe de triage profesional en español.

DATOS DEL ANALIZADO (ya normalizados por el motor local):
- Total de eventos: ${stats.total}
- Eventos sospechosos marcados: ${stats.flagged || 0}
- Equipos únicos: ${stats.hosts || 0}
- Cuentas únicas: ${stats.users || 0}
- IP externas observadas: ${(stats.externalIps || []).length}
- Incidentes correlacionados: ${incidents.length}

INCIDENTES DETECTADOS (JSON):
${JSON.stringify(incidentSummary, null, 2)}

ALERTAS POR REGLA DE DETECCIÓN (JSON):
${JSON.stringify(alertSummary, null, 2)}

CUENTAS POSIBLEMENTE COMPROMETIDAS: ${uniqueAccounts.length ? uniqueAccounts.join(', ') : 'ninguna'}
IP EXTERNAS DE INTERÉS: ${uniqueExternalIps.length ? uniqueExternalIps.join(', ') : 'ninguna'}

INSTRUCCIONES DE ANÁLISIS:
1. Actúa como si estuvieras revisando los logs en una consola SIEM/IDS/EDR real.
2. Identifica la cadena de ataque (kill chain): reconocimiento, arma, entrega, explotación, instalación, comando y control, acciones sobre objetivos.
3. Clasifica cada incidente por técnica MITRE ATT&CK más probable.
4. Indica qué indicadores de compromiso (IoC) son más críticos: IPs externas, cuentas comprometidas, hashes, dominios, URLs.
5. Evalúa el riesgo para el negocio y sugiere acciones de contención inmediata (0-4 horas), erradicación (24-48 horas) y recuperación.
6. Si no hay evidencia suficiente para afirmar un compromiso, dilo explícitamente como "sospecha no confirmada".
7. No inventes datos que no estén en los JSON anteriores.
8. Responde en español, tono profesional para dirección técnica y gerencia.
9. Estructura tu respuesta con secciones claras: Resumen Ejecutivo, Cadena de Ataque, Hallazgos Críticos, IoCs, Recomendaciones de Contención, Próximos Pasos.
`;
  }

  async function checkConnection(apiKey) {
    if (!apiKey || !apiKey.trim()) {
      return { ok: false, message: 'Introduce una clave API de Gemini válida.' };
    }
    try {
      const url = `${API_BASE}/models?key=${encodeURIComponent(apiKey.trim())}`;
      const r = await fetch(url);
      if (!r.ok) {
        const err = await r.json().catch(() => ({}));
        return { ok: false, message: `Error ${r.status}: ${err.error ? err.error.message : 'Clave API inválida o sin permisos.'}` };
      }
      const j = await r.json();
      const modelos = (j.models || []).map((m) => m.name).filter((n) => n.includes('gemini')).join(', ');
      return { ok: true, message: `Conexión exitosa. Modelos disponibles: ${modelos}`, models: j.models || [] };
    } catch (err) {
      return { ok: false, message: 'No se pudo conectar con la API de Gemini. Verifica tu conexión a internet y la clave API.' };
    }
  }

  async function analyzeWithGemini(apiKey, model, stats, events, incidents) {
    if (!apiKey || !apiKey.trim()) {
      throw new Error('Clave API de Gemini no proporcionada.');
    }
    const prompt = buildSiemPrompt(stats, events, incidents);
    const url = `${API_BASE}/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey.trim())}`;

    const body = {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        temperature: 0.3,
        maxOutputTokens: 4096,
        topP: 0.8,
        topK: 40
      }
    };

    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      throw new Error(err.error ? err.error.message : `Error HTTP ${r.status} al consultar Gemini.`);
    }

    const j = await r.json();
    const candidates = j.candidates || [];
    if (!candidates.length || !candidates[0].content || !candidates[0].content.parts) {
      throw new Error('La API no devolvió contenido de texto.');
    }
    const texto = candidates[0].content.parts.map((p) => p.text || '').join('\n');
    if (!texto.trim()) {
      throw new Error('La API devolvió una respuesta vacía.');
    }
    return texto;
  }

  function buildDiagnosisHtml(texto) {
    const html = `
      <div style="font-family: system-ui, -apple-system, sans-serif; line-height: 1.6; color:#1e293b;">
        <h3 style="margin-top:0; color:#0f172a; font-size:1.25rem; border-bottom:2px solid #0ea5e9; padding-bottom:0.5rem;">
          🧠 Análisis de Seguridad por IA (Google Gemini)
        </h3>
        <p style="font-size:0.875rem; color:#64748b; margin-bottom:1rem;">
          Generado con asistencia de inteligencia artificial. Este análisis debe ser revisado por un analista humano antes de ejecutar acciones de contención.
        </p>
        <div style="white-space: pre-wrap; font-size:0.9375rem; color:#334155;">${escapeHtml(texto)}</div>
        <p style="margin-top:1rem; font-size:0.8125rem; color:#64748b;">
          Generado por motor de IA de NODO SOC · Procesamiento local de logs + inferencia remota vía Gemini API.
        </p>
      </div>
    `;
    return html;
  }

  async function analyze(apiKey, model, stats, events, incidents) {
    const texto = await analyzeWithGemini(apiKey, model, stats, events, incidents);
    return buildDiagnosisHtml(texto);
  }

  global.AIAssistant = {
    analyze,
    checkConnection,
    buildSiemPrompt
  };
})(window);
