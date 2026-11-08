(function(window) {
    'use strict';

    function downloadCSV(data, filename = 'Exportacion_SOC_Logs.csv') {
        if (!data || !data.length) return;
        const keys = Object.keys(data[0]);
        const csvRows = [keys.join(',')];

        data.forEach(row => {
            const values = keys.map(k => `"${row[k] || ''}"`);
            csvRows.push(values.join(','));
        });

        const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        a.click();
    }

    window.XLSXLite = { exportCSV: downloadCSV };
})(window);
