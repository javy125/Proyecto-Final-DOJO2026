/**
 * Renderizador de gráficos nativos SVG para el dashboard SOC.
 * Genera gráficos con elementos SVG creados por JavaScript puro.
 * No depende de librerías externas ni de conexiones a internet.
 * Expone: window.ChartRenderer
 */
(function (global) {
  'use strict';

  const SEVERITY_COLORS = {
    CRITICAL: '#dc2626',
    HIGH: '#ea580c',
    MEDIUM: '#eab308',
    INFO: '#2563eb'
  };

  let selectedSeverity = null;

  function clearContainer(containerId) {
    const container = document.getElementById(containerId);
    if (container) {
      while (container.firstChild) {
        container.removeChild(container.firstChild);
      }
    }
  }

  function createSvgElement(tag, attrs, parent) {
    const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
    if (attrs) {
      for (const [key, value] of Object.entries(attrs)) {
        el.setAttribute(key, value);
      }
    }
    if (parent) parent.appendChild(el);
    return el;
  }

  function drawSvgText(parent, x, y, text, size, fill, anchor, weight) {
    const el = createSvgElement('text', {
      x: x,
      y: y,
      'text-anchor': anchor || 'start',
      'font-size': size,
      'font-weight': weight || 'normal',
      fill: fill || '#111827',
      'font-family': 'system-ui, -apple-system, sans-serif'
    }, parent);
    el.textContent = text;
    return el;
  }

  /* ---------- Gráfico de anillo: severidad ---------- */
  function drawSeverityChart(containerId, severityCounts, onClick) {
    const container = document.getElementById(containerId);
    if (!container) return;
    clearContainer(containerId);

    const width = 550;
    const height = 400;
    const centerX = width / 2;
    const centerY = height / 2 - 20;
    const outerRadius = 110;
    const innerRadius = 65;

    const labels = ['Crítico', 'Alto', 'Medio', 'Info'];
    const keys = ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO'];
    const values = [
      severityCounts['CRITICAL'] || 0,
      severityCounts['HIGH'] || 0,
      severityCounts['MEDIUM'] || 0,
      severityCounts['INFO'] || 0
    ];

    const total = values.reduce((sum, v) => sum + v, 0);

    const svg = createSvgElement('svg', {
      width: width,
      height: height,
      viewBox: `0 0 ${width} ${height}`,
      'role': 'img',
      'aria-label': 'Distribución de eventos por severidad',
      style: 'cursor: pointer;'
    }, container);

    // Fondo
    createSvgElement('rect', {
      x: 0, y: 0, width: width, height: height,
      fill: '#ffffff', rx: 8, ry: 8
    }, svg);

    if (total === 0) {
      drawSvgText(svg, centerX, centerY + 8, 'Sin datos de severidad', 14, '#64748b', 'middle', '600');
      return;
    }

    const colors = [SEVERITY_COLORS.CRITICAL, SEVERITY_COLORS.HIGH, SEVERITY_COLORS.MEDIUM, SEVERITY_COLORS.INFO];
    let currentAngle = -Math.PI / 2;

    keys.forEach((key, index) => {
      const value = values[index];
      if (value === 0) return;
      const sliceAngle = (value / total) * 2 * Math.PI;
      const endAngle = currentAngle + sliceAngle;

      const x1 = centerX + outerRadius * Math.cos(currentAngle);
      const y1 = centerY + outerRadius * Math.sin(currentAngle);
      const x2 = centerX + outerRadius * Math.cos(endAngle);
      const y2 = centerY + outerRadius * Math.sin(endAngle);
      const largeArc = sliceAngle > Math.PI ? 1 : 0;

      const pathData = 'M ' + centerX + ' ' + centerY + ' L ' + x1 + ' ' + y1 + ' A ' + outerRadius + ' ' + outerRadius + ' 0 ' + largeArc + ' 1 ' + x2 + ' ' + y2 + ' Z';

      const isSelected = selectedSeverity === key;
      const path = createSvgElement('path', {
        d: pathData,
        fill: colors[index] || '#94a3b8',
        stroke: isSelected ? '#ffffff' : '#ffffff',
        'stroke-width': isSelected ? 4 : 2,
        'data-severity': key,
        style: 'cursor: pointer;',
        filter: isSelected ? 'url(#glow)' : 'none'
      }, svg);

      if (isSelected) {
        const defs = createSvgElement('defs', {}, svg);
        createSvgElement('filter', {
          id: 'glow',
          x: '-20%', y: '-20%', width: '140%', height: '140%'
        }, defs);
        createSvgElement('feGaussianBlur', {
          stdDeviation: '3',
          result: 'blur'
        }, defs);
        createSvgElement('feComposite', {
          'in': 'SourceGraphic',
          'in2': 'blur',
          operator: 'over'
        }, defs);
      }

      // Evento click para filtrar
      path.addEventListener('click', (evt) => {
        evt.stopPropagation();
        if (selectedSeverity === key) {
          selectedSeverity = null;
          path.setAttribute('stroke-width', '2');
          path.removeAttribute('filter');
        } else {
          selectedSeverity = key;
          path.setAttribute('stroke-width', '4');
          path.setAttribute('filter', 'url(#glow)');
        }
        if (onClick) onClick(key);
        if (global.ChartRenderer && global.ChartRenderer.onSeverityChange) {
          global.ChartRenderer.onSeverityChange(key);
        }
      });

      const midAngle = currentAngle + sliceAngle / 2;
      const labelX = centerX + (outerRadius + 22) * Math.cos(midAngle);
      const labelY = centerY + (outerRadius + 22) * Math.sin(midAngle);
      const percent = Math.round((value / total) * 100);

      drawSvgText(svg, labelX, labelY, labels[index] + ' ' + percent + '%', 11, '#111827', 'middle', '600');

      currentAngle = endAngle;
    });

    // Título
    drawSvgText(svg, centerX, 32, 'Eventos por severidad', 16, '#334155', 'middle', '600');

    // Total en el centro
    drawSvgText(svg, centerX, centerY + 10, String(total), 32, '#111827', 'middle', '700');
    drawSvgText(svg, centerX, centerY + 36, 'eventos', 12, '#64748b', 'middle');
  }

  /* ---------- Gráfico de barras: categorías ---------- */
  function drawCategoryChart(containerId, categoryCounts, categorySeverity) {
    const container = document.getElementById(containerId);
    if (!container) return;
    clearContainer(containerId);

    const width = 550;
    const height = 400;
    const marginTop = 55;
    const marginRight = 40;
    const marginBottom = 85;
    const marginLeft = 65;
    const chartWidth = width - marginLeft - marginRight;
    const chartHeight = height - marginTop - marginBottom;

    const labels = Object.keys(categoryCounts);
    const values = Object.values(categoryCounts);

    const svg = createSvgElement('svg', {
      width: width,
      height: height,
      viewBox: `0 0 ${width} ${height}`,
      'role': 'img',
      'aria-label': 'Eventos por categoría'
    }, container);

    // Fondo
    createSvgElement('rect', {
      x: 0, y: 0, width: width, height: height,
      fill: '#ffffff', rx: 8, ry: 8
    }, svg);

    if (labels.length === 0) {
      drawSvgText(svg, width / 2, height / 2, 'Sin datos de categoría', 14, '#64748b', 'middle', '600');
      return;
    }

    const maxValue = Math.max(...values);
    const scaleY = chartHeight / maxValue;

    // Título
    drawSvgText(svg, width / 2, 28, 'Eventos por categoría', 16, '#334155', 'middle', '600');

    // Colores por severidad
    const SEV_COLORS = {
      CRITICAL: '#dc2626',
      HIGH: '#ea580c',
      MEDIUM: '#eab308',
      INFO: '#2563eb',
      DEFAULT: '#64748b'
    };

    // Eje Y y líneas de cuadrícula
    for (let i = 0; i <= 5; i++) {
      const value = Math.round((maxValue * i) / 5);
      const y = height - marginBottom - (value * scaleY);
      drawSvgText(svg, marginLeft - 12, y + 4, String(value), 11, '#64748b', 'end');
      createSvgElement('line', {
        x1: marginLeft, y1: y, x2: width - marginRight, y2: y,
        stroke: '#e2e8f0', 'stroke-width': 1
      }, svg);
    }

    // Barras con color según severidad de la categoría
    const barWidth = chartWidth / labels.length * 0.65;
    const barGap = (chartWidth / labels.length - barWidth) / 2;

    values.forEach((value, index) => {
      const x = marginLeft + index * (chartWidth / labels.length) + barGap;
      const barHeight = value * scaleY;
      const y = height - marginBottom - barHeight;
      const sev = categorySeverity ? categorySeverity[labels[index]] : null;
      const barColor = SEV_COLORS[sev] || SEV_COLORS.DEFAULT;

      createSvgElement('rect', {
        x: x, y: y, width: barWidth, height: barHeight,
        fill: barColor, rx: 6, ry: 6
      }, svg);

      // Valor encima de la barra
      drawSvgText(svg, x + barWidth / 2, y - 8, String(value), 11, '#111827', 'middle', '700');

      // Etiqueta del eje X (truncada si es larga)
      const label = labels[index];
      const labelText = label.length > 18 ? label.slice(0, 17) + '…' : label;
      drawSvgText(svg, x + barWidth / 2, height - marginBottom + 16, labelText, 9, '#64748b', 'middle');
    });

    // Línea base del eje X
    createSvgElement('line', {
      x1: marginLeft, y1: height - marginBottom,
      x2: width - marginRight, y2: height - marginBottom,
      stroke: '#94a3b8', 'stroke-width': 1.5
    }, svg);
  }

  function setSelectedSeverity(sev) {
    selectedSeverity = sev;
  }

  function getSelectedSeverity() {
    return selectedSeverity;
  }

  global.ChartRenderer = {
    drawSeverity: drawSeverityChart,
    drawCategory: drawCategoryChart,
    setSelectedSeverity: setSelectedSeverity,
    getSelectedSeverity: getSelectedSeverity
  };
})(window);
