(function(window) {
    'use strict';

    function exportGlobalPDF(summary) {
        const rows = summary.logs.map(l => `
            <tr>
                <td>${l.timestamp}</td>
                <td>${l.sourceIp}</td>
                <td>${l.destinationIp}</td>
                <td>${l.category}</td>
                <td>${l.severity}</td>
                <td>${l.action}</td>
            </tr>
        `).join('');

        const html = `
            <div class="card-box">
                <p><strong>Total Registros:</strong> ${summary.metrics.total}</p>
                <p><strong>Incidentes Críticos:</strong> ${summary.metrics.critical}</p>
            </div>
            <h2>Tabla Completa de Eventos</h2>
            <table>
                <thead>
                    <tr><th>Fecha</th><th>Origen</th><th>Destino</th><th>Categoría</th><th>Severidad</th><th>Acción</th></tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        `;
        window.PDFExporter.print("Reporte Global de Incidentes SOC", html);
    }

    window.SOCReportManager = { buildGlobalPDF: exportGlobalPDF };
})(window);
