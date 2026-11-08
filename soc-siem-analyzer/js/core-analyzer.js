/**
 * Núcleo de análisis de telemetría SOC.
 * Normaliza registros, ejecuta reglas de detección, clasifica riesgo y
 * genera incidentes correlacionados. Expone: window.SIEMAnalyzer
 */
(function (global) {
  'use strict';

  const SEVERITY_ORDER = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  function severityRank(level) { return SEVERITY_ORDER.indexOf(String(level).toUpperCase()) || 0; }
  function maxSeverity(a, b) { return severityRank(a) >= severityRank(b) ? a : b; }

  const CONFIG = {
    bruteForceWindowMinutes: 10,
    bruteForceThreshold: 4,
    passwordSprayUsers: 3,
    successAfterFailureMinutes: 30,
    massAccessWindowMinutes: 10,
    massAccessThreshold: 8,
    exfiltrationBytesThreshold: 50 * 1024 * 1024,
    exfiltrationWindowMinutes: 60,
    correlationWindowMinutes: 120,
    businessHours: [7, 20]
  };

  const COLUMN_ALIASES = {
    id: ['log_id', 'id', 'event_record', 'logid'],
    timestamp: ['timestamp', 'time', 'fecha', 'date', '@timestamp', 'datetime'],
    host: ['hostname', 'host', 'computer', 'equipo'],
    eventId: ['event_id', 'eventid', 'event code', 'id_evento'],
    user: ['user', 'username', 'usuario', 'account'],
    sourceIp: ['source_ip', 'src_ip', 'ip_origen', 'sourceip', 'ip'],
    destinationIp: ['destination', 'dest', 'destino', 'dst_ip', 'destination_ip'],
    logSource: ['log_source', 'source', 'channel', 'fuente'],
    description: ['event_description', 'description', 'descripcion', 'message', 'mensaje'],
    command: ['process_commandline', 'commandline', 'command_line', 'process', 'comando'],
    result: ['result', 'resultado', 'status', 'outcome'],
    severity: ['severity', 'severidad', 'level', 'nivel']
  };

  function mapColumns(headers) {
    const mapping = {};
    const lowered = headers.map((h) => String(h).toLowerCase().trim());
    for (const [key, aliases] of Object.entries(COLUMN_ALIASES)) {
      const idx = lowered.findIndex((h) => aliases.includes(h));
      if (idx >= 0) mapping[key] = headers[idx];
    }
    return mapping;
  }

  function parseTimestamp(value) {
    if (!value) return null;
    const match = String(value).match(/(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/);
    if (match) return new Date(Date.UTC(+match[1], +match[2] - 1, +match[3], +match[4], +match[5], +(match[6] || 0)));
    const parsed = new Date(value);
    return isNaN(parsed) ? null : parsed;
  }

  function normalizeRecords(rawRows) {
    if (!rawRows.length) return { events: [], columnMap: {} };
    const columnMap = mapColumns(Object.keys(rawRows[0]));
    const get = (row, key) => (columnMap[key] ? String(row[columnMap[key]] ?? '').trim() : '');

    const events = rawRows.map((row, index) => {
      const evt = {
        recordId: get(row, 'id') || `ROW-${index + 2}`,
        timestampRaw: get(row, 'timestamp'),
        host: get(row, 'host'),
        eventId: get(row, 'eventId'),
        user: get(row, 'user'),
        sourceIp: get(row, 'sourceIp'),
        destinationIp: get(row, 'destinationIp'),
        logSource: get(row, 'logSource'),
        description: get(row, 'description'),
        command: get(row, 'command'),
        result: get(row, 'result'),
        severity: get(row, 'severity'),
        raw: row
      };
      evt.time = parseTimestamp(evt.timestampRaw);
      evt.epoch = evt.time ? evt.time.getTime() : 0;
      evt.shortUser = evt.user.replace(/^.*\\/, '');
      evt.fullText = `${evt.description} ${evt.command}`;
      return evt;
    }).sort((a, b) => a.epoch - b.epoch);

    return { events, columnMap };
  }

  function isPrivateIp(ip) {
    const match = String(ip).match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)/);
    if (!match) return true;
    const [a, b] = [+match[1], +match[2]];
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
  }

  const extractIp = (s) => (String(s).match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/) || [])[1] || '';
  const isPublicIp = (s) => { const ip = extractIp(s); return !!ip && !isPrivateIp(ip); };
  const subnet24 = (ip) => ip.split('.').slice(0, 3).join('.') + '.0/24';
  const MINUTE_MS = 60000;
  const uniqueValues = (arr) => [...new Set(arr.filter(Boolean))];
  const formatBytes = (bytes) => (bytes >= 1048576 ? (bytes / 1048576).toFixed(1) + ' MB' : (bytes / 1024).toFixed(1) + ' KB');
  const getLogonType = (evt) => (evt.description.match(/LogonType=(\d+)/i) || [])[1] || '';
  const GENERIC_ACCOUNTS = new Set(['', '-', 'system', 'n/a', 'anonymous logon', 'local service', 'network service']);
  const userPivot = (u) => (GENERIC_ACCOUNTS.has(u.toLowerCase()) ? null : 'user:' + u.toLowerCase());

  function groupByTimeWindow(list, minutes, threshold) {
    const groups = [];
    let i = 0;
    while (i < list.length) {
      let j = i;
      while (j + 1 < list.length && list[j + 1].epoch - list[i].epoch <= minutes * MINUTE_MS) j++;
      while (j + 1 < list.length && list[j + 1].epoch - list[j].epoch <= minutes * MINUTE_MS && j - i + 1 >= threshold) j++;
      if (j - i + 1 >= threshold) { groups.push(list.slice(i, j + 1)); i = j + 1; } else i++;
    }
    return groups;
  }

  let alertSequence = 0;
  function createAlert(options) {
    const evts = options.events || [];
    alertSequence++;
    return Object.assign({
      alertId: 'ALT-' + String(alertSequence).padStart(3, '0'),
      startTime: evts.length ? Math.min(...evts.map((e) => e.epoch)) : 0,
      endTime: evts.length ? Math.max(...evts.map((e) => e.epoch)) : 0,
      hosts: uniqueValues(evts.map((e) => e.host)),
      users: uniqueValues(evts.map((e) => e.shortUser)),
      ips: uniqueValues(evts.map((e) => e.sourceIp)),
      mitre: [],
      pivots: []
    }, options);
  }

  const DETECTION_RULES = [];

  function ruleBruteForce(events) {
    const results = [];
    const failures = events.filter((e) => e.eventId === '4625' || /failed to log ?on|fallo de inicio/i.test(e.description));
    const byIp = {};
    failures.forEach((e) => (byIp[e.sourceIp] = byIp[e.sourceIp] || []).push(e));

    for (const [ip, windowList] of Object.entries(byIp)) {
      for (const window of groupByTimeWindow(windowList, CONFIG.bruteForceWindowMinutes, CONFIG.bruteForceThreshold)) {
        const users = uniqueValues(window.map((e) => e.shortUser));
        const external = isPublicIp(ip);
        const rdp = window.some((e) => getLogonType(e) === '10');
        const spray = users.length >= CONFIG.passwordSprayUsers;

        results.push(createAlert({
          ruleId: 'R1', category: 'Fuerza bruta',
          title: spray ? `Password spraying desde ${ip}` : `Fuerza bruta${rdp ? ' RDP' : ''} contra ${users[0]} desde ${ip}`,
          severity: external ? 'HIGH' : 'MEDIUM',
          events: window,
          detail: `${window.length} intentos fallidos en ${Math.round((window[window.length - 1].epoch - window[0].epoch) / MINUTE_MS) || 1} min contra ${users.length} cuenta(s) (${users.join(', ')}) en ${uniqueValues(window.map((e) => e.host)).join(', ')}. Origen ${external ? 'EXTERNO' : 'interno'}${rdp ? ', RDP (LogonType 10)' : ''}.`,
          mitre: [spray ? ['T1110.003', 'Password Spraying'] : ['T1110.001', 'Password Guessing']].concat(rdp ? [['T1021.001', 'Remote Desktop Protocol']] : []),
          pivots: ['ip:' + ip],
          external: external
        }));

        const successes = events.filter((e) => e.sourceIp === ip && (e.eventId === '4624' || /successfully logged on/i.test(e.description)) &&
          e.epoch >= window[0].epoch && e.epoch - window[window.length - 1].epoch <= CONFIG.successAfterFailureMinutes * MINUTE_MS);
        successes.forEach((s) => {
          results.push(createAlert({
            ruleId: 'R1b', category: 'Inicio sospechoso',
            title: `Inicio exitoso tras fuerza bruta: ${s.shortUser} desde ${ip}`,
            severity: external ? 'CRITICAL' : 'HIGH',
            events: [s],
            detail: `Tras ${window.length} fallos, la cuenta ${s.shortUser} inicia sesión en ${s.host} desde ${ip}${getLogonType(s) ? ' (LogonType ' + getLogonType(s) + ')' : ''}. Indica credenciales comprometidas.`,
            mitre: [['T1078', 'Valid Accounts']].concat(getLogonType(s) === '10' ? [['T1021.001', 'Remote Desktop Protocol']] : []),
            pivots: ['ip:' + ip, userPivot(s.shortUser)].filter(Boolean),
            compromised: true
          }));
        });
      }
    }
    return results;
  }

  function ruleSuspiciousLogon(events, previousAlerts) {
    const covered = new Set(previousAlerts.flatMap((a) => (a.ruleId === 'R1b' ? a.events.map((e) => e.recordId) : [])));
    const results = [];

    events.filter((e) => (e.eventId === '4624' || /successfully logged on/i.test(e.description)) && !covered.has(e.recordId)).forEach((e) => {
      const hour = e.time ? e.time.getUTCHours() : 12;
      if (isPublicIp(e.sourceIp)) {
        results.push(createAlert({
          ruleId: 'R2', category: 'Inicio sospechoso', title: `Inicio desde IP pública ${e.sourceIp} (${e.shortUser})`,
          severity: 'HIGH', events: [e],
          detail: `Sesión válida en ${e.host} desde Internet; los accesos legítimos deberían provenir de la red interna o VPN.`,
          mitre: [['T1133', 'External Remote Services'], ['T1078', 'Valid Accounts']],
          pivots: ['ip:' + e.sourceIp, userPivot(e.shortUser)].filter(Boolean),
          compromised: true
        }));
      } else if (hour < CONFIG.businessHours[0] || hour >= CONFIG.businessHours[1]) {
        results.push(createAlert({
          ruleId: 'R2b', category: 'Inicio sospechoso', title: `Inicio fuera de horario (${e.shortUser} en ${e.host})`,
          severity: 'LOW', events: [e],
          detail: `Sesión a las ${e.timestampRaw.slice(11, 16)}, fuera del horario laboral configurado.`,
          mitre: [['T1078', 'Valid Accounts']], pivots: []
        }));
      }
    });
    return results;
  }

  function rulePrivilegeEscalation(events, previousAlerts) {
    const results = [];
    const suspectSessions = previousAlerts.filter((a) => a.compromised).flatMap((a) => a.events.map((e) => ({ u: e.shortUser, ip: e.sourceIp, t: e.epoch })));

    events.filter((e) => e.eventId === '4672' || /special privileges/i.test(e.description)).forEach((e) => {
      const linked = suspectSessions.find((s) => (s.u === e.shortUser || s.ip === e.sourceIp) && Math.abs(e.epoch - s.t) <= 15 * MINUTE_MS);
      const external = isPublicIp(e.sourceIp);
      if (linked || external) {
        results.push(createAlert({
          ruleId: 'R3', category: 'Escalamiento de privilegios', title: `Privilegios administrativos asignados a ${e.shortUser} en ${e.host}`,
          severity: 'HIGH', events: [e],
          detail: `Evento 4672 (privilegios especiales, p. ej. SeDebugPrivilege) en una sesión ${external ? 'originada desde Internet (' + e.sourceIp + ')' : 'vinculada a un acceso sospechoso'}.`,
          mitre: [['T1078.002', 'Domain Accounts'], ['T1068', 'Privilege Escalation']],
          pivots: [userPivot(e.shortUser), external ? 'ip:' + e.sourceIp : null].filter(Boolean)
        }));
      }
    });
    return results;
  }

  const COMMAND_PATTERNS = [
    { re: /-e(nc|ncodedcommand)?\s+\S|-encodedcommand/i, sev: 'HIGH', type: 'PowerShell con comando codificado (Base64)', mitre: [['T1059.001', 'PowerShell'], ['T1027', 'Obfuscated Files or Information']], why: 'El parámetro -EncodedCommand oculta el contenido real del script.' },
    { re: /vssadmin(\.exe)?\s+delete\s+shadows|wbadmin\s+delete|bcdedit.*recoveryenabled\s+no|wmic\s+shadowcopy\s+delete/i, sev: 'CRITICAL', type: 'Borrado de copias de seguridad (Volume Shadow Copies)', mitre: [['T1490', 'Inhibit System Recovery']], why: 'Eliminar instantáneas impide recuperar archivos; paso previo al cifrado por ransomware.' },
    { re: /mimikatz|sekurlsa|lsass.*dump|procdump.*lsass|comsvcs.*minidump/i, sev: 'CRITICAL', type: 'Volcado de credenciales', mitre: [['T1003', 'OS Credential Dumping']], why: 'Extracción de credenciales de memoria.' },
    { re: /\b(tar|7z|rar|winrar|makecab)(\.exe)?\b.*\.(zip|7z|rar|cab|tar)|compress-archive/i, sev: 'HIGH', type: 'Compresión de datos para extracción (staging)', mitre: [['T1560.001', 'Archive via Utility'], ['T1074.001', 'Local Data Staging']], why: 'Empaquetar información precede a la exfiltración.' },
    { re: /certutil.*-urlcache|bitsadmin.*\/transfer|invoke-webrequest|downloadstring|iex\s*\(/i, sev: 'HIGH', type: 'Descarga de herramientas desde Internet', mitre: [['T1105', 'Ingress Tool Transfer']], why: 'Uso de utilidades nativas para descargar cargas útiles.' },
    { re: /\bnet(\.exe)?\s+(view|user|group|localgroup)\b|nltest|get-(local|ad)groupmember|get-aduser|whoami\s+\/(groups|priv|all)/i, sev: 'MEDIUM', type: 'Reconocimiento de red y cuentas', mitre: [['T1087', 'Account Discovery'], ['T1135', 'Network Share Discovery'], ['T1069', 'Permission Groups Discovery']], why: 'Enumeración de recursos compartidos, grupos o administradores.' },
    { re: /\bwhoami\b/i, sev: 'MEDIUM', type: 'Comando de identificación (whoami)', mitre: [['T1033', 'System Owner/User Discovery']], why: 'El atacante verifica con qué cuenta ejecuta comandos.' },
    { re: /psexec|wmic\s+\/node|winrs|invoke-command\s+-computername|enter-pssession/i, sev: 'HIGH', type: 'Ejecución remota en otro equipo', mitre: [['T1021', 'Remote Services'], ['T1047', 'WMI']], why: 'Herramientas de ejecución remota usadas para movimiento lateral.' }
  ];

  function ruleSuspiciousCommands(events) {
    const results = [];
    events.forEach((e) => {
      const text = `${e.command} ${e.description}`;
      const webProc = /apppool|w3wp|iis/i.test(e.user + ' ' + e.description + ' ' + e.command) && /cmd\.exe|powershell|whoami/i.test(text);
      if (webProc) {
        results.push(createAlert({
          ruleId: 'R4w', category: 'Ataque web', title: `Webshell: servidor web ejecuta comandos (${e.command || e.description})`,
          severity: 'CRITICAL', events: [e],
          detail: `La identidad del pool de aplicaciones de IIS (${e.user}) lanzó "${e.command}" en ${e.host}. Un servidor web nunca debería abrir cmd.exe: confirma ejecución remota de código.`,
          mitre: [['T1505.003', 'Web Shell'], ['T1190', 'Exploit Public-Facing Application'], ['T1059.003', 'Windows Command Shell']],
          pivots: [isPublicIp(e.sourceIp) ? 'ip:' + e.sourceIp : null, 'host:' + e.host.toLowerCase() + ':web'].filter(Boolean),
          compromised: true
        }));
        return;
      }
      if (/http_access|proxy_access/i.test(e.eventId) || /^(iis|proxy|firewall)$/i.test(e.logSource)) return;
      if (!e.command && !/script block|new process/i.test(e.description)) return;
      for (const pattern of COMMAND_PATTERNS) {
        if (pattern.re.test(text)) {
          results.push(createAlert({
            ruleId: 'R4', category: 'Comandos y procesos', title: `${pattern.type} en ${e.host}`, severity: pattern.sev, events: [e],
            detail: `${e.shortUser} ejecutó: ${(e.command && e.command !== 'powershell.exe' ? e.command : e.description).slice(0, 160)}. ${pattern.why}`,
            mitre: pattern.mitre,
            pivots: [userPivot(e.shortUser), isPublicIp(e.sourceIp) ? 'ip:' + e.sourceIp : null].filter(Boolean),
            impact: pattern.sev === 'CRITICAL' ? 'ransomware' : null
          }));
          break;
        }
      }
    });
    return results;
  }

  function rulePersistence(events) {
    const results = [];
    events.filter((e) => ['4698', '7045', '4697'].includes(e.eventId) || /scheduled task was created|service was installed/i.test(e.description)).forEach((e) => {
      const suspicious = /programdata|\\temp\\|appdata|\\users\\public|powershell|\.ps1|cmd\.exe/i.test(e.command);
      const masquerade = /microsoft|windows|update/i.test(e.command) && suspicious;
      const isTask = e.eventId === '4698' || /task/i.test(e.description);
      results.push(createAlert({
        ruleId: 'R5', category: 'Persistencia', title: `${isTask ? 'Tarea programada creada' : 'Servicio creado'} en ${e.host}${masquerade ? ' imitando a Windows Update' : ''}`,
        severity: suspicious ? 'HIGH' : 'MEDIUM', events: [e],
        detail: `${e.shortUser} registró: ${e.command}. ${suspicious ? 'El binario/script reside en una ruta escribible por usuarios y usa nombre que imita componentes legítimos de Windows: patrón clásico de persistencia.' : 'Revisar si corresponde a un cambio autorizado.'}`,
        mitre: [isTask ? ['T1053.005', 'Scheduled Task'] : ['T1543.003', 'Windows Service']].concat(masquerade ? [['T1036.004', 'Masquerade Task or Service']] : []),
        pivots: [userPivot(e.shortUser), 'persistence:' + e.host.toLowerCase()].filter(Boolean)
      }));
    });
    return results;
  }

  function ruleLateralMovement(events, previousAlerts) {
    const results = [];
    events.filter((e) => /source=([\w.-]+)/i.test(e.description) && /LogonType=3/i.test(e.description)).forEach((e) => {
      const srcHost = e.description.match(/source=([\w.-]+)/i)[1];
      const ok = /success/i.test(e.description) || /success/i.test(e.result);
      results.push(createAlert({
        ruleId: 'R6', category: 'Movimiento lateral', title: `${ok ? 'Acceso' : 'Intento de acceso'} de red ${srcHost} → ${e.host} con cuenta ${e.shortUser}`,
        severity: ok ? 'HIGH' : 'MEDIUM', events: [e],
        detail: `Autenticación de red (LogonType 3) desde el servidor ${srcHost} hacia ${e.host}.`,
        mitre: [['T1021.002', 'SMB/Windows Admin Shares'], ['T1078', 'Valid Accounts']],
        pivots: [userPivot(e.shortUser), 'host:' + srcHost.toLowerCase()].filter(Boolean)
      }));
    });
    const hotUsers = new Set(previousAlerts.filter((a) => severityRank(a.severity) >= 2).flatMap((a) => a.pivots.filter((p) => p.startsWith('user:'))));
    events.filter((e) => ['5140', '5145'].includes(e.eventId) && /finance|legal|rrhh|hr\b|nomina|payroll|contab/i.test(e.fullText + ' ' + e.destinationIp)).forEach((e) => {
      const pu = userPivot(e.shortUser);
      if (pu && hotUsers.has(pu)) {
        results.push(createAlert({
          ruleId: 'R6b', category: 'Exfiltración de datos', title: `Acceso a recurso sensible ${/\\/.test(e.destinationIp) ? e.destinationIp : (e.description.split(': ')[1] || e.destinationIp)} por ${e.shortUser}`,
          severity: 'HIGH', events: [e],
          detail: `La cuenta ${e.shortUser}, ya implicada en actividad maliciosa, accede a información sensible: ${e.description}.`,
          mitre: [['T1039', 'Data from Network Shared Drive']], pivots: [pu]
        }));
      }
    });
    return results;
  }

  function ruleMassFileAccess(events) {
    const results = [];
    const byGroup = {};
    events.filter((e) => e.eventId === '4663' || /access an object/i.test(e.description)).forEach((e) => {
      const k = e.user + '|' + e.host + '|' + e.destinationIp;
      (byGroup[k] = byGroup[k] || []).push(e);
    });
    for (const list of Object.values(byGroup)) {
      for (const window of groupByTimeWindow(list, CONFIG.massAccessWindowMinutes, CONFIG.massAccessThreshold)) {
        const resource = uniqueValues(window.map((e) => e.destinationIp)).join(', ');
        results.push(createAlert({
          ruleId: 'R7', category: 'Exfiltración de datos', title: `Acceso masivo a archivos: ${window.length} archivos en ${Math.max(1, Math.round((window[window.length - 1].epoch - window[0].epoch) / MINUTE_MS))} min (${window[0].shortUser})`,
          severity: 'HIGH', events: window,
          detail: `La cuenta ${window[0].shortUser} abrió ${window.length} archivos en ${resource || window[0].host} a intervalos regulares (patrón automatizado). Puede tratarse de recolección para robo de datos o cifrado por ransomware.`,
          mitre: [['T1005', 'Data from Local System'], ['T1039', 'Data from Network Shared Drive']],
          pivots: [userPivot(window[0].shortUser)].filter(Boolean)
        }));
      }
    }
    return results;
  }

  function ruleExfiltration(events) {
    const results = [];
    const posts = events.filter((e) => /bytes_out=\d+/i.test(e.command + e.description));
    const byGroup = {};
    posts.forEach((e) => { const k = e.host + '|' + e.destinationIp; (byGroup[k] = byGroup[k] || []).push(e); });

    for (const list of Object.values(byGroup)) {
      const total = list.reduce((s, e) => s + parseInt((e.command + e.description).match(/bytes_out=(\d+)/i)[1], 10), 0);
      if (total >= CONFIG.exfiltrationBytesThreshold && list[list.length - 1].epoch - list[0].epoch <= CONFIG.exfiltrationWindowMinutes * MINUTE_MS) {
        const e0 = list[0];
        results.push(createAlert({
          ruleId: 'R8', category: 'Exfiltración de datos', title: `Exfiltración: ${formatBytes(total)} enviados a ${e0.destinationIp} desde ${e0.host}`,
          severity: 'CRITICAL', events: list,
          detail: `${list.length} peticiones HTTPS POST en ${Math.round((list[list.length - 1].epoch - e0.epoch) / MINUTE_MS)} min (${e0.shortUser}) hacia ${e0.destinationIp}, con URIs secuenciales (/upload/session/N). Volumen y patrón incompatibles con navegación normal.`,
          mitre: [['T1048.002', 'Exfiltration Over Asymmetric Encrypted Non-C2 Protocol'], ['T1567', 'Exfiltration Over Web Service']],
          pivots: [userPivot(e0.shortUser), 'ip:' + extractIp(e0.destinationIp)].filter(Boolean),
          impact: 'exfil',
          bytes: total
        }));
      }
    }

    events.filter((e) => (e.eventId === '5156' || /outbound connection/i.test(e.description)) && isPublicIp(e.destinationIp) && /powershell|cmd|rundll32|mshta|wscript|tar|curl/i.test(e.command + e.description)).forEach((e) => {
      results.push(createAlert({
        ruleId: 'R8b', category: 'Exfiltración de datos', title: `Conexión saliente de ${(e.command || 'proceso').split(' ')[0]} hacia ${e.destinationIp}`,
        severity: 'HIGH', events: [e],
        detail: `Un intérprete de comandos abrió una conexión a Internet (${e.destinationIp}) desde ${e.host}. Combinado con compresión previa, es indicativo de envío de información o canal de comando y control.`,
        mitre: [['T1041', 'Exfiltration Over C2 Channel'], ['T1071.001', 'Web Protocols']],
        pivots: [userPivot(e.shortUser), 'ip:' + extractIp(e.destinationIp)].filter(Boolean),
        impact: 'exfil'
      }));
    });
    return results;
  }

  function ruleWebAttacks(events) {
    const results = [];
    const http = events.filter((e) => /http_access|iis|w3c/i.test(e.eventId + ' ' + e.logSource));
    const byIp = {};
    http.forEach((e) => (byIp[e.sourceIp] = byIp[e.sourceIp] || []).push(e));
    const PAT = /cmd=|exec=|\.\.\/|union\s+select|<script|\/etc\/passwd|\.aspx\?|\.php\?|\/uploads\/.*\.(aspx|php|jsp)/i;
    for (const [ip, list] of Object.entries(byIp)) {
      const malicious = list.filter((e) => PAT.test(e.command + e.description));
      const probes = list.filter((e) => /\/admin|\/login\?user=admin|\/api\/.*export|wp-admin|phpmyadmin/i.test(e.command));
      const errors = list.filter((e) => /^[45]\d\d$/.test(e.result));
      if (malicious.length || probes.length >= 5) {
        results.push(createAlert({
          ruleId: 'R9', category: 'Ataque web', title: `Ataque a aplicación web desde ${ip}`, severity: malicious.length ? 'HIGH' : 'MEDIUM', events: list,
          detail: `${list.length} peticiones automatizadas en ${Math.max(1, Math.round((list[list.length - 1].epoch - list[0].epoch) / MINUTE_MS))} min contra ${uniqueValues(list.map((e) => e.host)).join(', ')}: ${malicious.length} con intento de ejecución de comandos, ${probes.length} sondeos a /admin, /login y /api/export, ${errors.length} respuestas de error 4xx/5xx.`,
          mitre: [['T1190', 'Exploit Public-Facing Application'], ['T1595.003', 'Wordlist Scanning'], ['T1505.003', 'Web Shell']],
          pivots: ['ip:' + ip], external: isPublicIp(ip)
        }));
      }
    }
    return results;
  }

  function ruleAnomalies(events, previousAlerts) {
    const results = [];
    const normalize = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, '');
    const groupByKey = (vals) => {
      const g = {};
      vals.forEach((v) => { const k = normalize(v); (g[k] = g[k] || new Set()).add(v); });
      return Object.values(g).filter((s) => s.size > 1).map((s) => [...s]);
    };

    const hosts = uniqueValues(events.map((e) => e.host));
    groupByKey(hosts).forEach((names) => {
      const evs = events.filter((e) => names.includes(e.host));
      const counts = names.map((n) => `${n} (${evs.filter((e) => e.host === n).length} eventos)`).join(' y ');
      results.push(createAlert({
        ruleId: 'R10', category: 'Otras anomalías', title: `Nombres de equipo casi idénticos: ${names.join(' / ')}`, severity: 'MEDIUM',
        events: evs.filter((e) => e.host === names.sort((a, b) => evs.filter((x) => x.host === a).length - evs.filter((x) => x.host === b).length)[0]),
        detail: `Se registran ${counts}. Puede ser un error de inventario o un equipo no autorizado que imita al controlador de dominio.`,
        mitre: [['T1036', 'Masquerading']], pivots: []
      }));
    });

    const users = uniqueValues(events.map((e) => e.shortUser)).filter((u) => !GENERIC_ACCOUNTS.has(u.toLowerCase()));
    const seen = new Set();
    users.forEach((a) => users.forEach((b) => {
      const na = normalize(a), nb = normalize(b);
      if (a < b && na !== nb && na.length === nb.length && na.length >= 6 && (na + na).includes(nb) && !seen.has(a + b)) {
        seen.add(a + b);
        const ea = events.filter((e) => e.shortUser === a), eb = events.filter((e) => e.shortUser === b);
        const sus = [...ea, ...eb].filter((e) => /warning|high|medium/i.test(e.severity));
        results.push(createAlert({
          ruleId: 'R10b', category: 'Otras anomalías', title: `Cuentas de servicio con nombres casi iguales: ${a} / ${b}`, severity: 'MEDIUM',
          events: ea.filter((e) => !isPublicIp(e.sourceIp)).slice(0, 3).concat(eb.filter((e) => !isPublicIp(e.sourceIp)).slice(0, 3)),
          detail: `Conviven ${a} (${ea.length} eventos) y ${b} (${eb.length} eventos). Una podría ser creada por el atacante para pasar desapercibida. ${sus.length ? 'La actividad maliciosa observada usa ' + uniqueValues(sus.map((e) => e.shortUser)).join(', ') + '.' : ''}`,
          mitre: [['T1136', 'Create Account'], ['T1036', 'Masquerading']], pivots: []
        }));
      }
    }));

    const covered = new Set(previousAlerts.concat(results).flatMap((a) => a.events.map((e) => e.recordId)));
    const remaining = events.filter((e) => /^(high|critical|alta|crítica)$/i.test(e.severity) && !covered.has(e.recordId));
    if (remaining.length) {
      results.push(createAlert({
        ruleId: 'R10c', category: 'Otras anomalías', title: `${remaining.length} evento(s) de severidad alta sin regla específica`, severity: 'MEDIUM', events: remaining,
        detail: 'El SIEM los marcó como High; requieren revisión manual.', mitre: [], pivots: uniqueValues(remaining.map((e) => userPivot(e.shortUser)))
      }));
    }
    return results;
  }

  function correlateAlerts(alerts) {
    const parent = alerts.map((_, i) => i);
    function find(i) { return parent[i] === i ? i : (parent[i] = find(parent[i])); }
    function union(a, b) { parent[find(a)] = find(b); }

    for (let i = 0; i < alerts.length; i++) {
      for (let j = i + 1; j < alerts.length; j++) {
        const A = alerts[i], B = alerts[j];
        const gap = Math.max(0, Math.max(A.startTime, B.startTime) - Math.min(A.endTime, B.endTime));
        if (gap > CONFIG.correlationWindowMinutes * MINUTE_MS) continue;
        if (A.pivots.some((p) => B.pivots.includes(p))) union(i, j);
      }
    }

    const groups = {};
    alerts.forEach((a, i) => (groups[find(i)] = groups[find(i)] || []).push(a));
    return Object.values(groups).map((g) => g.sort((a, b) => a.startTime - b.startTime));
  }

  function nameIncident(categories, alerts) {
    const has = (c) => categories.includes(c);
    const rdp = alerts.some((a) => a.mitre.some((m) => m[0] === 'T1021.001'));
    if (has('Ataque web') && alerts.some((a) => a.ruleId === 'R4w')) return 'Compromiso del servidor web mediante webshell';
    if (has('Ataque web')) return 'Ataque automatizado contra la aplicación web';
    if (alerts.some((a) => a.impact === 'ransomware')) return 'Actividad precursora de ransomware (recolección masiva y borrado de copias)';
    if (has('Movimiento lateral') && has('Exfiltración de datos')) return `Intrusión ${rdp ? 'por RDP ' : ''}con movimiento lateral y exfiltración de datos`;
    if (has('Fuerza bruta') && alerts.some((a) => a.compromised)) return alerts.some((a) => /spraying/i.test(a.title)) ? 'Password spraying con compromiso de cuenta' : 'Fuerza bruta con acceso exitoso';
    if (has('Exfiltración de datos') && alerts.some((a) => a.ruleId === 'R8')) return alerts.some((a) => a.compromised) ? 'Exfiltración de datos por canal web' : 'Robo de información: compresión y exfiltración por HTTPS';
    if (has('Exfiltración de datos')) return 'Exfiltración de datos';
    if (has('Persistencia')) return 'Mecanismos de persistencia no autorizados';
    if (has('Fuerza bruta')) return 'Intentos de fuerza bruta';
    return alerts[0].title;
  }

  const IMPACT_DESCRIPTIONS = {
    'Fuerza bruta': 'Riesgo de toma de control de cuentas corporativas y bloqueo masivo de usuarios.',
    'Inicio sospechoso': 'Un tercero dispone de credenciales válidas y puede actuar como un empleado legítimo.',
    'Escalamiento de privilegios': 'Con privilegios de administrador el atacante puede desactivar defensas, crear cuentas y acceder a cualquier dato del equipo.',
    'Comandos y procesos': 'Ejecución de código arbitrario en servidores/estaciones; base para robo de credenciales, reconocimiento y despliegue de malware.',
    'Movimiento lateral': 'La intrusión deja de estar contenida en un equipo y alcanza servidores críticos (archivos, finanzas).',
    'Exfiltración de datos': 'Pérdida de confidencialidad de información financiera/corporativa; posibles obligaciones de notificación y daño reputacional.',
    'Persistencia': 'El atacante conserva acceso aunque se cambien contraseñas o se reinicie el equipo.',
    'Ataque web': 'Control remoto del servidor expuesto a Internet, punto de entrada para el resto de la red.',
    'Otras anomalías': 'Debilita la confianza en el inventario y facilita que activos o cuentas maliciosas pasen inadvertidos.'
  };

  const ACTION_PLANS = {
    'Fuerza bruta': { inv: ['Revisar 4625/4624 de la IP origen y su reputación.', 'Identificar qué cuentas lograron autenticarse.'], con: ['Bloquear IP/rango en firewall.', 'Forzar cambio de contraseña y revocar sesiones.'], rem: ['Activar MFA en accesos expuestos.', 'Política de bloqueo de cuenta y alertas por spraying.'] },
    'Inicio sospechoso': { inv: ['Reconstruir la sesión: equipos tocados y duración.', 'Confirmar con el usuario si reconoce el acceso.'], con: ['Deshabilitar temporalmente la cuenta y cerrar sesiones.'], rem: ['Restringir accesos remotos a VPN con MFA.'] },
    'Escalamiento de privilegios': { inv: ['Auditar pertenencia a grupos privilegiados y cambios recientes.'], con: ['Retirar privilegios de cuentas implicadas; restablecer contraseñas administrativas.'], rem: ['Modelo de niveles (tiering) y LAPS.'] },
    'Comandos y procesos': { inv: ['Decodificar comandos Base64 y obtener scripts.', 'Adquirir memoria y artefactos (Prefetch, Amcache, logs 4104).'], con: ['Aislar equipos afectados desde el EDR.'], rem: ['PowerShell Constrained Language Mode, Script Block Logging y AppLocker/WDAC.'] },
    'Movimiento lateral': { inv: ['Mapear autenticaciones LogonType 3/10 entre servidores.'], con: ['Segmentar: bloquear SMB/RDP entre servidores salvo flujos autorizados.'], rem: ['Microsegmentación y cuentas de servicio con permisos mínimos.'] },
    'Exfiltración de datos': { inv: ['Determinar qué archivos salieron y a qué destino.', 'Consultar logs de proxy/firewall completos.'], con: ['Bloquear dominios/IP de destino en proxy y firewall; aislar equipo origen.'], rem: ['DLP en proxy, alertas por volumen saliente anómalo, inspección TLS.'] },
    'Persistencia': { inv: ['Extraer y analizar archivos en C:\\ProgramData.', 'Buscar el mismo artefacto en el resto del parque.'], con: ['Deshabilitar y eliminar tarea/servicio; poner en cuarentena el binario.'], rem: ['Alertas para 4698/7045 fuera de ventanas de cambio.'] },
    'Ataque web': { inv: ['Localizar y preservar el archivo webshell.', 'Revisar qué devolvió /api/v1/export.'], con: ['Retirar el webshell, bloquear IP en WAF.'], rem: ['Prohibir ejecución en /uploads, validar extensiones, WAF con reglas OWASP.'] },
    'Otras anomalías': { inv: ['Contrastar nombres de equipos y cuentas con el inventario/AD.'], con: ['Deshabilitar el activo o cuenta no reconocidos.'], rem: ['Normalizar nombres en fuentes de logs y gobierno de cuentas de servicio.'] }
  };

  function classifyIncident(incident) {
    const alerts = incident.alerts;
    let severity = alerts.reduce((s, a) => maxSeverity(s, a.severity), 'INFO');
    const factors = [];
    const compromised = alerts.some((a) => a.compromised);
    const impact = alerts.find((a) => a.impact);
    const categories = incident.categories;

    if (compromised) factors.push('hay acceso confirmado al entorno (credenciales válidas o ejecución de código)');
    if (impact && impact.impact === 'exfil') factors.push('existe evidencia de salida de datos hacia Internet');
    if (impact && impact.impact === 'ransomware') factors.push('se eliminaron copias de seguridad de volumen, señal típica previa a un ataque de ransomware');
    if (categories.includes('Movimiento lateral')) factors.push('el atacante se desplazó a otros servidores');
    if (categories.includes('Escalamiento de privilegios')) factors.push('obtuvo privilegios administrativos');
    if (categories.includes('Persistencia')) factors.push('dejó mecanismos para mantener el acceso');
    if (alerts.some((a) => a.external)) factors.push('el origen es una IP pública de Internet');

    if (compromised && (impact || categories.length >= 3)) severity = 'CRITICAL';
    if (!compromised && categories.includes('Persistencia') && severityRank(severity) < 2) severity = 'HIGH';

    const descriptions = {
      'CRITICAL': 'Actividad maliciosa con impacto confirmado o inminente sobre confidencialidad, integridad o disponibilidad. Requiere respuesta inmediata.',
      'HIGH': 'Actividad maliciosa clara con riesgo elevado; el impacto aún no está confirmado. Respuesta en horas.',
      'MEDIUM': 'Anomalía o intento sin éxito comprobado; requiere verificación en la jornada.',
      'INFO': 'Evento informativo o de higiene; seguimiento planificado.'
    };
    incident.severity = severity;
    incident.justification = `${descriptions[severity]}${factors.length ? ' Factores: ' + factors.join('; ') + '.' : ''}`;
  }

  function buildIncidents(groups, events) {
    const incidents = groups.map((alerts) => {
      const eventIds = uniqueValues(alerts.flatMap((a) => a.events.map((e) => e.recordId)));
      const evs = events.filter((e) => eventIds.includes(e.recordId));
      const categories = uniqueValues(alerts.map((a) => a.category));
      const incident = {
        alerts, categories, events: evs,
        startTime: Math.min(...alerts.map((a) => a.startTime)), endTime: Math.max(...alerts.map((a) => a.endTime)),
        hosts: uniqueValues(alerts.flatMap((a) => a.hosts)),
        users: uniqueValues(alerts.flatMap((a) => a.users)).filter((u) => !GENERIC_ACCOUNTS.has(u.toLowerCase())),
        ips: uniqueValues(alerts.flatMap((a) => a.ips)),
        externalIps: uniqueValues(evs.flatMap((e) => [extractIp(e.sourceIp), extractIp(e.destinationIp)]).filter((ip) => ip && !isPrivateIp(ip))),
        mitre: uniqueValues(alerts.flatMap((a) => a.mitre.map((m) => m[0] + ' ' + m[1])))
      };
      incident.title = nameIncident(categories, alerts);
      classifyIncident(incident);
      incident.impact = categories.map((c) => IMPACT_DESCRIPTIONS[c]).filter(Boolean);
      const plan = { inv: [], con: [], rem: [] };
      categories.forEach((c) => { const p = ACTION_PLANS[c]; if (p) ['inv', 'con', 'rem'].forEach((k) => plan[k].push(...p[k])); });
      incident.plan = { inv: uniqueValues(plan.inv), con: uniqueValues(plan.con), rem: uniqueValues(plan.rem) };
      return incident;
    }).sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.startTime - b.startTime);

    incidents.forEach((inc, i) => { inc.incidentId = 'INC-' + String(i + 1).padStart(2, '0'); inc.related = []; });
    for (const a of incidents) for (const b of incidents) {
      if (a === b) continue;
      const shared = a.externalIps.filter((x) => b.externalIps.some((y) => subnet24(x) === subnet24(y)));
      if (shared.length) a.related.push({ id: b.id, why: 'infraestructura del atacante en la misma red ' + uniqueValues(shared.map(subnet24)).join(', ') });
      const hs = a.hosts.filter((h) => b.hosts.includes(h) && h !== '');
      if (hs.length && !shared.length && !a.categories.includes('Otras anomalías') && !b.categories.includes('Otras anomalías')) a.related.push({ id: b.id, why: 'comparten activos afectados: ' + hs.join(', ') });
    }
    return incidents;
  }

  function analyze(rawRows) {
    alertSequence = 0;
    const { events, columnMap } = normalizeRecords(rawRows);
    let alerts = [];
    for (const rule of DETECTION_RULES) alerts = alerts.concat(rule(events, alerts));
    const incidents = buildIncidents(correlateAlerts(alerts), events);
    const flagged = new Set(alerts.flatMap((a) => a.events.map((e) => e.recordId)));
    events.forEach((e) => {
      const inc = incidents.find((i) => i.events.some((x) => x.recordId === e.recordId));
      e.incidentId = inc ? inc.incidentId : '';
      e.riskLevel = inc ? inc.severity : '';
      e.flagged = flagged.has(e.recordId);
    });
    return { events, columnMap, alerts, incidents, config: CONFIG, stats: computeStats(events, incidents, alerts) };
  }

  function computeStats(events, incidents, alerts) {
    const count = (arr, fn) => arr.reduce((m, x) => { const k = fn(x) || '(vacío)'; m[k] = (m[k] || 0) + 1; return m; }, {});
    const epochs = events.filter((e) => e.epoch).map((e) => e.epoch);
    const byCategorySeverity = {};
    alerts.forEach((a) => {
      const cat = a.category || '(vacío)';
      if (!byCategorySeverity[cat] || severityRank(a.severity) > severityRank(byCategorySeverity[cat])) {
        byCategorySeverity[cat] = a.severity;
      }
    });
    return {
      total: events.length,
      flagged: events.filter((e) => e.flagged).length,
      hosts: uniqueValues(events.map((e) => e.host)).length,
      users: uniqueValues(events.map((e) => e.shortUser)).length,
      startTime: epochs.length ? Math.min(...epochs) : 0,
      endTime: epochs.length ? Math.max(...epochs) : 0,
      bySeverity: count(incidents, (i) => i.severity),
      byCategory: count(alerts, (a) => a.category),
      byCategorySeverity,
      byEventId: count(events, (e) => e.eventId),
      byHost: count(events.filter((e) => e.flagged), (e) => e.host),
      bySiemSeverity: count(events, (e) => e.severity),
      externalIps: uniqueValues(events.flatMap((e) => [extractIp(e.sourceIp), extractIp(e.destinationIp)]).filter((ip) => ip && !isPrivateIp(ip)))
    };
  }

  DETECTION_RULES.push(
    ruleBruteForce,
    ruleSuspiciousLogon,
    rulePrivilegeEscalation,
    ruleSuspiciousCommands,
    rulePersistence,
    ruleLateralMovement,
    ruleMassFileAccess,
    ruleExfiltration,
    ruleWebAttacks,
    ruleAnomalies
  );

  const SIEMAnalyzer = { analyze, CONFIG, SEVERITY_ORDER, severityRank, formatBytes, isPrivateIp };
  if (typeof module !== 'undefined' && module.exports) module.exports = SIEMAnalyzer;
  else global.SIEMAnalyzer = SIEMAnalyzer;
})(window);
