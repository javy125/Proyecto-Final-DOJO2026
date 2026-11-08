/**
 * Visualización gráfica para métricas del Dashboard SOC.
 */
(function(window) {
    'use strict';

    let chartSev = null;
    let chartCat = null;

    function drawCharts(metrics) {
        const ctxSev = document.getElementById('chart-severity');
        const ctxCat = document.getElementById('chart-category');

        if (!ctxSev || !ctxCat) return;

        if (chartSev) chartSev.destroy();
        if (chartCat) chartCat.destroy();

        chartSev = new Chart(ctxSev, {
            type: 'pie',
            data: {
                labels: ['Crítico', 'Alto', 'Medio', 'Info'],
                datasets: [{
                    data: [metrics.severities.CRITICAL, metrics.severities.HIGH, metrics.severities.MEDIUM, metrics.severities.INFO],
                    backgroundColor: ['#ef233c', '#ffb703', '#48cae4', '#8d99ae']
                }]
            },
            options: { responsive: true, plugins: { legend: { labels: { color: '#edf2f4' } } } }
        });

        chartCat = new Chart(ctxCat, {
            type: 'bar',
            data: {
                labels: Object.keys(metrics.categories),
                datasets: [{
                    label: 'Ocurrencias',
                    data: Object.values(metrics.categories),
                    backgroundColor: '#48cae4'
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { labels: { color: '#edf2f4' } } },
                scales: { x: { ticks: { color: '#edf2f4' } }, y: { ticks: { color: '#edf2f4' } } }
            }
        });
    }

    window.SOCCharts = { draw: drawCharts };
})(window);
