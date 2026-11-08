/**
 * Engine central de procesamiento, normalización y filtrado de telemetría SIEM.
 */
(function(window) {
    'use strict';

    class SIEMDataEngine {
        constructor() {
            this.originalLogs = [];
            this.currentLogs = [];
        }

        loadDataset(records) {
            this.originalLogs = records.map((item, idx) => this._standardizeRow(item, idx));
            this.currentLogs = [...this.originalLogs];
            return this.getSummary();
        }

        _standardizeRow(row, idx) {
            return {
                id: row.id || `INC-${1000 + idx}`,
                timestamp: row.timestamp || row.Date || row.Tiempo || new Date().toISOString().replace('T', ' ').substring(0, 19),
                sourceIp: row.source_ip || row.SrcIP || row.Origen || '192.168.1.' + Math.floor(Math.random() * 254),
                destinationIp: row.dest_ip || row.DstIP || row.Destino || '10.0.0.' + Math.floor(Math.random() * 254),
                category: row.category || row.Category || row.Evento || 'Actividad Sospechosa',
                severity: String(row.severity || row.Level || row.Severidad || 'MEDIUM').toUpperCase(),
                action: row.action || row.Action || row.Accion || 'BLOQUEADO',
                description: row.description || `Evento detectado en el vector ${row.category || 'General'}.`
            };
        }

        getSummary() {
            const metrics = {
                total: this.currentLogs.length,
                critical: 0,
                high: 0,
                medium: 0,
                info: 0,
                categories: {},
                severities: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, INFO: 0 }
            };

            this.currentLogs.forEach(log => {
                const sev = log.severity;
                if (metrics.severities[sev] !== undefined) metrics.severities[sev]++;
                else metrics.severities.MEDIUM++;

                if (sev === 'CRITICAL') metrics.critical++;
                else if (sev === 'HIGH') metrics.high++;
                else if (sev === 'MEDIUM') metrics.medium++;
                else metrics.info++;

                metrics.categories[log.category] = (metrics.categories[log.category] || 0) + 1;
            });

            return { logs: this.currentLogs, metrics };
        }

        removeDuplicates() {
            const seen = new Set();
            const initialCount = this.currentLogs.length;
            this.currentLogs = this.currentLogs.filter(log => {
                const key = `${log.timestamp}-${log.sourceIp}-${log.category}`;
                if (seen.has(key)) return false;
                seen.add(key);
                return true;
            });
            return initialCount - this.currentLogs.length;
        }

        purgeInfoLogs() {
            const initialCount = this.currentLogs.length;
            this.currentLogs = this.currentLogs.filter(log => log.severity !== 'INFO' && log.severity !== 'LOW');
            return initialCount - this.currentLogs.length;
        }

        resetLogs() {
            this.currentLogs = [...this.originalLogs];
            return this.currentLogs.length;
        }
    }

    window.SIEMEngine = new SIEMDataEngine();
})(window);
