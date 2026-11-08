/**
 * Generador de documentos PDF limpio y profesional.
 * Diseño independiente del tema de la UI - fondo blanco, texto oscuro,
 * estructura clara y legible para impresión.
 * Expone: window.PDFGenerator
 */
(function (global) {
  'use strict';

  const PAGE_WIDTH = 595.28, PAGE_HEIGHT = 841.89, MARGEN = 54, CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGEN;

  /* ---------- Paleta de colores profesional ---------- */
  const C = {
    ink: [0.11, 0.14, 0.2],
    surface: [1, 1, 1],
    surfaceAlt: [0.97, 0.97, 0.99],
    border: [0.88, 0.90, 0.93],
    navy: [0.06, 0.11, 0.2],
    accent: [0.06, 0.58, 0.88],
    muted: [0.46, 0.48, 0.55],
    light: [0.92, 0.94, 0.96],
    white: [1, 1, 1],
    'Crítico': [0.92, 0.27, 0.27],
    'Alto': [0.98, 0.55, 0.12],
    'Medio': [0.92, 0.70, 0.15],
    'Bajo': [0.23, 0.51, 0.96],
    'CRITICAL': [0.92, 0.27, 0.27],
    'HIGH': [0.98, 0.55, 0.12],
    'MEDIUM': [0.92, 0.70, 0.15],
    'INFO': [0.23, 0.51, 0.96],
    'LOW': [0.23, 0.51, 0.96]
  };

  const CP1252_MAP = {
    0x20ac: 0x80, 0x201a: 0x82, 0x192: 0x83, 0x201e: 0x84, 0x2026: 0x85,
    0x2020: 0x86, 0x2021: 0x87, 0x2c6: 0x88, 0x2030: 0x89, 0x160: 0x8a,
    0x2039: 0x8b, 0x152: 0x8c, 0x17d: 0x8e, 0x2018: 0x91, 0x2019: 0x92,
    0x201c: 0x93, 0x201d: 0x94, 0x2022: 0x95, 0x2013: 0x96, 0x2014: 0x97,
    0x2dc: 0x98, 0x2122: 0x99, 0x161: 0x9a, 0x203a: 0x9b, 0x153: 0x9c,
    0x17e: 0x9e, 0x178: 0x9f
  };

  const SUBSTITUTIONS = { '→': '->', '≥': '>=', '≤': '<=', '×': 'x', '✓': 'OK', '\t': ' ' };

  const defaultFontTable = [];
  for (let i = 0; i < 256; i++) defaultFontTable[i] = 556;
  defaultFontTable[32] = 278; defaultFontTable[33] = 278; defaultFontTable[34] = 355; defaultFontTable[35] = 556;
  defaultFontTable[36] = 556; defaultFontTable[37] = 889; defaultFontTable[38] = 667; defaultFontTable[39] = 191;
  defaultFontTable[40] = 333; defaultFontTable[41] = 333; defaultFontTable[42] = 389; defaultFontTable[43] = 584;
  defaultFontTable[44] = 278; defaultFontTable[45] = 333; defaultFontTable[46] = 278; defaultFontTable[47] = 278;
  defaultFontTable[48] = 556; defaultFontTable[49] = 556; defaultFontTable[50] = 556; defaultFontTable[51] = 556;
  defaultFontTable[52] = 556; defaultFontTable[53] = 556; defaultFontTable[54] = 556; defaultFontTable[55] = 556;
  defaultFontTable[56] = 556; defaultFontTable[57] = 556; defaultFontTable[65] = 722; defaultFontTable[66] = 722;
  defaultFontTable[67] = 722; defaultFontTable[68] = 722; defaultFontTable[69] = 722; defaultFontTable[70] = 722;
  defaultFontTable[71] = 722; defaultFontTable[72] = 722; defaultFontTable[73] = 722; defaultFontTable[74] = 722;
  defaultFontTable[75] = 722; defaultFontTable[76] = 722; defaultFontTable[77] = 722; defaultFontTable[78] = 722;
  defaultFontTable[79] = 722; defaultFontTable[80] = 722; defaultFontTable[81] = 722; defaultFontTable[82] = 722;
  defaultFontTable[83] = 722; defaultFontTable[84] = 722; defaultFontTable[85] = 722; defaultFontTable[86] = 722;
  defaultFontTable[87] = 722; defaultFontTable[88] = 722; defaultFontTable[89] = 722; defaultFontTable[90] = 722;
  defaultFontTable[97] = 556; defaultFontTable[98] = 556; defaultFontTable[99] = 556; defaultFontTable[100] = 556;
  defaultFontTable[101] = 556; defaultFontTable[102] = 556; defaultFontTable[103] = 556; defaultFontTable[104] = 556;
  defaultFontTable[105] = 556; defaultFontTable[106] = 556; defaultFontTable[107] = 556; defaultFontTable[108] = 556;
  defaultFontTable[109] = 556; defaultFontTable[110] = 556; defaultFontTable[111] = 556; defaultFontTable[112] = 556;
  defaultFontTable[113] = 556; defaultFontTable[114] = 556; defaultFontTable[115] = 556; defaultFontTable[116] = 556;
  defaultFontTable[117] = 556; defaultFontTable[118] = 556; defaultFontTable[119] = 556; defaultFontTable[120] = 556;
  defaultFontTable[121] = 556; defaultFontTable[122] = 556;

  function encodeText(text) {
    let output = '';
    for (const ch of String(text ?? '')) {
      if (SUBSTITUTIONS[ch]) { output += SUBSTITUTIONS[ch]; continue; }
      const code = ch.codePointAt(0);
      if (code < 32) continue;
      if (code < 128 || (code >= 160 && code < 256)) output += String.fromCharCode(code);
      else if (CP1252_MAP[code]) output += String.fromCharCode(CP1252_MAP[code]);
      else output += '?';
    }
    return output;
  }

  const escapePdf = (s) => s.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
  const rgbString = (color) => color.map((v) => v.toFixed(3)).join(' ');

  /* ---------- Clase DocumentoPDF ---------- */
  function PdfDocument() {
    this.pages = [];
    this.y = MARGEN + 20;
    this.newPage();
  }

  PdfDocument.prototype.newPage = function () {
    this.current = [];
    this.pages.push(this.current);
    this.y = MARGEN + 20;
  };

  PdfDocument.prototype.textWidth = function (text, size, font) {
    if (font === 'mono') return encodeText(text).length * 0.55 * size;
    const table = font === 'bold' ? (global.HELV_BOLD || global.HELV || defaultFontTable) : (global.HELV_REGULAR || global.HELV || defaultFontTable);
    if (!table) return encodeText(text).length * 0.5 * size;
    let width = 0;
    const encoded = encodeText(text);
    for (let i = 0; i < encoded.length; i++) width += table[encoded.charCodeAt(i)] || 556;
    return (width / 1000) * size;
  };

  PdfDocument.prototype.wrapText = function (text, size, font, maxWidth) {
    const lines = [];
    String(text ?? '').split('\n').forEach((paragraph) => {
      let line = '';
      paragraph.split(/\s+/).filter(Boolean).forEach((word) => {
        while (this.textWidth(word, size, font) > maxWidth) {
          let k = word.length;
          while (k > 1 && this.textWidth(word.slice(0, k), size, font) > maxWidth) k--;
          if (line) { lines.push(line); line = ''; }
          lines.push(word.slice(0, k));
          word = word.slice(k);
        }
        const combined = line ? line + ' ' + word : word;
        if (this.textWidth(combined, size, font) <= maxWidth) line = combined;
        else { if (line) lines.push(line); line = word; }
      });
      lines.push(line);
    });
    return lines;
  };

  PdfDocument.prototype.drawText = function (text, x, y, size, font, color) {
    const face = font === 'bold' ? 'F2' : font === 'mono' ? 'F3' : 'F1';
    this.current.push(`BT /${face} ${size} Tf ${rgbString(color || C.ink)} rg ${x.toFixed(2)} ${(PAGE_HEIGHT - y).toFixed(2)} Td (${escapePdf(encodeText(text))}) Tj ET`);
  };

  PdfDocument.prototype.drawRect = function (x, y, width, height, color) {
    this.current.push(`${rgbString(color)} rg ${x.toFixed(2)} ${(PAGE_HEIGHT - y - height).toFixed(2)} ${width.toFixed(2)} ${height.toFixed(2)} re f`);
  };

  PdfDocument.prototype.drawLine = function (x1, x2, y, color, thickness) {
    this.current.push(`${rgbString(color)} RG ${thickness || 0.5} w ${x1.toFixed(2)} ${(PAGE_HEIGHT - y).toFixed(2)} m ${x2.toFixed(2)} ${(PAGE_HEIGHT - y).toFixed(2)} l S`);
  };

  PdfDocument.prototype.ensureSpace = function (height) {
    if (this.y + height > PAGE_HEIGHT - MARGEN - 10) this.newPage();
  };

  PdfDocument.prototype.writeParagraph = function (text, options) {
    const opt = Object.assign({ size: 9.5, font: 'regular', color: C.ink, x: MARGEN, width: CONTENT_WIDTH, lineHeight: 1.5 }, options || {});
    const lines = this.wrapText(text, opt.size, opt.font, opt.width);
    lines.forEach((line) => {
      this.ensureSpace(opt.size * opt.lineHeight);
      this.drawText(line, opt.x, this.y + opt.size, opt.size, opt.font, opt.color);
      this.y += opt.size * opt.lineHeight;
    });
  };

  PdfDocument.prototype.drawSeverityBadge = function (label, x, y, size) {
    const s = size || 7;
    const w = this.textWidth(label, s, 'bold') + 10;
    this.drawRect(x, y, w, s + 5, C[label] || C.muted);
    this.drawText(label, x + 5, y + s + 1.5, s, 'bold', label === 'MEDIUM' ? [0.1, 0.08, 0] : C.white);
    return w;
  };

  PdfDocument.prototype.buildTable = function (header, widths, rows, small) {
    const fontSize = small ? 7.2 : 8.2, padding = 4, lineHeight = fontSize * 1.35;
    const scale = CONTENT_WIDTH / widths.reduce((a, b) => a + b, 0);
    const colWidths = widths.map((w) => w * scale);

    const drawHeader = () => {
      const wrappedHeader = header.map((h, i) => this.wrapText(h, fontSize, 'bold', colWidths[i] - 2 * padding));
      const headerHeight = Math.max(...wrappedHeader.map((l) => l.length)) * lineHeight + 2 * padding;
      this.ensureSpace(headerHeight + 10);
      this.drawRect(MARGEN, this.y, CONTENT_WIDTH, headerHeight, C.navy);
      let x = MARGEN;
      wrappedHeader.forEach((lines, i) => {
        lines.forEach((line, k) => this.drawText(line, x + padding, this.y + padding + fontSize + k * lineHeight, fontSize, 'bold', C.white));
        x += colWidths[i];
      });
      this.y += headerHeight;
    };

    drawHeader();

    rows.forEach((row, rowIndex) => {
      const cells = row.map((cell, i) => {
        const isSeverity = C[cell] && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(cell);
        const font = small && i < 6 ? 'mono' : 'regular';
        return { severity: isSeverity, font, lines: isSeverity ? [cell] : this.wrapText(cell, fontSize, font, colWidths[i] - 2 * padding) };
      });
      const rowHeight = Math.max(...cells.map((c) => c.lines.length)) * lineHeight + 2 * padding;
      if (this.y + rowHeight > PAGE_HEIGHT - MARGEN - 10) { this.newPage(); drawHeader(); }
      if (rowIndex % 2 === 1) this.drawRect(MARGEN, this.y, CONTENT_WIDTH, rowHeight, C.surfaceAlt);
      let x = MARGEN;
      cells.forEach((cell, i) => {
        if (cell.severity) this.drawSeverityBadge(cell.lines[0], x + padding, this.y + padding - 1, fontSize - 0.5);
        else cell.lines.forEach((l, k) => this.drawText(l, x + padding, this.y + padding + fontSize + k * lineHeight, fontSize, cell.font, C.ink));
        x += colWidths[i];
      });
      this.y += rowHeight;
      this.drawLine(MARGEN, MARGEN + CONTENT_WIDTH, this.y, C.border, 0.4);
    });
    this.y += 8;
  };

  /* ---------- Renderizado de bloques ---------- */
  function renderBlocks(blocks, metadata) {
    const doc = new PdfDocument();

    const m = metadata || {};
    const metaClient = m.client || 'Cliente corporativo';
    const metaRef = m.ref || 'SOC-' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-01';
    const metaAnalyst = m.analyst || 'Analista SOC';

    blocks.forEach((block) => {
      switch (block.type) {
        case 'cover': {
          doc.drawRect(0, 0, PAGE_WIDTH, PAGE_HEIGHT, C.white);
          doc.drawRect(0, PAGE_HEIGHT - 120, PAGE_WIDTH, 120, C.navy);
          doc.drawRect(MARGEN, PAGE_HEIGHT - 124, 4, 4, C.accent);

          doc.drawText('NODO SOC — INFORME DE SEGURIDAD', MARGEN, 100, 10, 'bold', C.accent);

          doc.y = 150;
          doc.wrapText(block.subtitle, 11, 'regular', CONTENT_WIDTH).forEach((line) => {
            doc.drawText(line, MARGEN, doc.y + 2, 11, 'regular', [0.8, 0.85, 0.9]);
            doc.y += 13;
          });

          doc.y += 25;

          const col1X = MARGEN + 20;
          const col2X = MARGEN + 160;
          const rowHeight = 18;

          block.keyValue.filter((kv) => kv[1]).forEach((kv, rowIdx) => {
            const y = doc.y;
            const bgColor = (rowIdx % 2 === 0) ? C.white : C.surfaceAlt;

            doc.drawRect(MARGEN, doc.y, CONTENT_WIDTH, 16, bgColor);

            doc.drawText(kv[0], col1X, doc.y + 4, 8.5, 'bold', C.muted);

            const valueText = String(kv[1]).length > 45 ? String(kv[1]).slice(0, 42) + '...' : kv[1];
            doc.drawText(valueText, col2X, doc.y + 4, 9, 'regular', C.ink);

            doc.y += rowHeight;
          });
          doc.newPage();
          break;
        }
        case 'heading2': {
          doc.ensureSpace(50);
          doc.drawRect(MARGEN, doc.y + 2, 3, 16, C.accent);
          doc.drawText(block.text, MARGEN + 12, doc.y + 16, 14, 'bold', C.navy);
          doc.y += 28;
          doc.drawLine(MARGEN, MARGEN + CONTENT_WIDTH, doc.y, C.border, 0.5);
          doc.y += 10;
          break;
        }
        case 'heading3': {
          doc.ensureSpace(45);
          if (block.severity) {
            const bw = doc.drawSeverityBadge(block.severity, MARGEN, doc.y + 2, 8);
            doc.drawText(block.text, MARGEN + bw + 8, doc.y + 10, 11.5, 'bold', C.navy);
            doc.y += 18;
          } else {
            doc.drawText(block.text, MARGEN, doc.y + 2, 11.5, 'bold', C.navy);
            doc.y += 14;
          }
          break;
        }
        case 'heading4':
          doc.ensureSpace(30);
          doc.drawText(block.text.toUpperCase(), MARGEN, doc.y + 2, 8.5, 'bold', [0.78, 0.35, 0.16]);
          doc.y += 14;
          break;
        case 'paragraph':
          doc.writeParagraph(block.text, { color: block.muted ? C.muted : C.ink, size: block.muted ? 8.5 : 9.5 });
          doc.y += 4;
          break;
        case 'box': {
          const lines = doc.wrapText(block.text, 9.2, 'regular', CONTENT_WIDTH - 22);
          const height = lines.length * 13 + 14;
          doc.ensureSpace(Math.min(height, 220));
          if (doc.y + height > PAGE_HEIGHT - MARGEN - 10) {
            doc.writeParagraph(block.text, { x: MARGEN + 10, width: CONTENT_WIDTH - 20, size: 9.2 });
            doc.y += 6;
            break;
          }
          doc.drawRect(MARGEN, doc.y, CONTENT_WIDTH, height, C.surfaceAlt);
          doc.drawRect(MARGEN, doc.y, 3, height, C.accent);
          lines.forEach((l, i) => doc.drawText(l, MARGEN + 13, doc.y + 7 + 10 + i * 13, 9.2, 'regular', C.ink));
          doc.y += height + 8;
          break;
        }
        case 'list':
          block.items.forEach((item) => {
            const lines = doc.wrapText(item, 9.2, 'regular', CONTENT_WIDTH - 24);
            doc.ensureSpace(lines.length * 13 + 6);
            doc.drawText('•', MARGEN + 2, doc.y + 2, 9.2, 'bold', C.accent);
            lines.forEach((l, i) => doc.drawText(l, MARGEN + 14, doc.y + 9.5 + i * 13, 9.2, 'regular', C.ink));
            doc.y += lines.length * 13 + 3;
          });
          doc.y += 4;
          break;
        case 'keyValue':
          block.keyValue.forEach((kv) => {
            const lines = doc.wrapText(kv[1], 9.2, 'regular', CONTENT_WIDTH - 120);
            doc.ensureSpace(lines.length * 13 + 4);
            doc.drawText(kv[0], MARGEN, doc.y + 9.5, 8.5, 'bold', C.muted);
            if (kv[0] === 'Criticidad' && C[kv[1]]) doc.drawSeverityBadge(kv[1], MARGEN + 110, doc.y, 7);
            else lines.forEach((l, i) => doc.drawText(l, MARGEN + 110, doc.y + 9.5 + i * 13, 9.2, 'regular', C.ink));
            doc.y += lines.length * 13 + 4;
          });
          doc.y += 5;
          break;
        case 'steps':
          block.items.forEach((step) => {
            const titleLines = doc.wrapText(step[1], 9.2, 'bold', CONTENT_WIDTH - 72);
            const detailLines = doc.wrapText(step[2], 8.8, 'regular', CONTENT_WIDTH - 72);
            const height = titleLines.length * 12.5 + detailLines.length * 12 + 8;
            doc.ensureSpace(Math.min(height, 130));
            doc.drawRect(MARGEN + 52, doc.y + 2, 5, 5, C.accent);
            doc.drawText(step[0], MARGEN, doc.y + 9, 8, 'mono', C.muted);
            titleLines.forEach((l, i) => doc.drawText(l, MARGEN + 66, doc.y + 9.2 + i * 12.5, 9.2, 'bold', C.ink));
            let yy = doc.y + titleLines.length * 12.5;
            detailLines.forEach((l) => {
              if (yy + 12 > PAGE_HEIGHT - MARGEN - 10) { doc.newPage(); yy = doc.y; }
              doc.drawText(l, MARGEN + 66, yy + 8, 8.8, 'regular', [0.3, 0.35, 0.4]); yy += 12;
            });
            doc.y = yy + 7;
          });
          break;
        case 'table':
          doc.buildTable(block.header, block.widths, block.rows, block.small);
          break;
        case 'actionPlan':
          doc.buildTable(['INVESTIGAR', 'CONTENER', 'REMEDIAR'], [1, 1, 1], [[block.investigate, block.contain, block.remediate].map((a) => a.map((x) => '• ' + x).join('\n'))]);
          break;
        case 'severityBars': {
          doc.ensureSpace(65);
          const barWidth = (CONTENT_WIDTH - 30) / 4;
          block.data.forEach((item, i) => {
            const x = MARGEN + i * (barWidth + 10);
            doc.drawRect(x, doc.y, barWidth, 48, C.surfaceAlt);
            doc.drawRect(x, doc.y, barWidth, 3, C[item[0]]);
            doc.drawText(String(item[1]), x + 10, doc.y + 28, 20, 'bold', C[item[0]]);
            doc.drawText(item[0], x + 10, doc.y + 46, 8.5, 'bold', C.ink);
          });
          doc.y += 60;
          break;
        }
        case 'pageBreak':
          if (doc.y > MARGEN + 120) doc.newPage();
          break;
      }
    });

    const totalPages = doc.pages.length;
    doc.pages.forEach((page, index) => {
      if (index === 0) return;
      page.push(`${rgbString(C.border)} RG 0.5 w ${MARGEN} ${PAGE_HEIGHT - 30} m ${PAGE_WIDTH - MARGEN} ${PAGE_HEIGHT - 30} l S`);
      page.push(`BT /F1 7.5 Tf ${rgbString(C.muted)} rg ${MARGEN} ${PAGE_HEIGHT - 24} Td (${escapePdf(encodeText('Informe de seguridad SOC'))}) Tj ET`);
      page.push(`BT /F1 7.5 Tf ${rgbString(C.muted)} rg ${PAGE_WIDTH - MARGEN - 100} ${PAGE_HEIGHT - 24} Td (${escapePdf(encodeText('CONFIDENCIAL · ' + metaRef))}) Tj ET`);
      page.push(`BT /F1 7.5 Tf ${rgbString(C.muted)} rg ${MARGEN} 24 Td (${escapePdf(encodeText(metaAnalyst + ' · Analista SOC Nivel 3'))}) Tj ET`);
      page.push(`BT /F1 7.5 Tf ${rgbString(C.muted)} rg ${PAGE_WIDTH - MARGEN - 50} 24 Td (${escapePdf(encodeText(`Página ${index + 1} de ${totalPages}`))}) Tj ET`);
    });

    return serializeDocument(doc.pages, metadata, metaAnalyst);
  }

  function serializeDocument(pages, metadata, metaAnalyst) {
    const objects = [];
    const addObject = (content) => { objects.push(content); return objects.length; };
    const catalogRef = addObject(null);
    const pagesRef = addObject(null);
    const font1 = addObject('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
    const font2 = addObject('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
    const font3 = addObject('<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>');
    const pageKids = [];

    pages.forEach((operations) => {
      const contentStream = operations.join('\n');
      const streamRef = addObject(`<< /Length ${contentStream.length} >>\nstream\n${contentStream}\nendstream`);
      pageKids.push(addObject(`<< /Type /Page /Parent ${pagesRef} 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] /Resources << /Font << /F1 ${font1} 0 R /F2 ${font2} 0 R /F3 ${font3} 0 R >> >> /Contents ${streamRef} 0 R >>`));
    });

    objects[catalogRef - 1] = `<< /Type /Catalog /Pages ${pagesRef} 0 R >>`;
    objects[pagesRef - 1] = `<< /Type /Pages /Kids [${pageKids.map((k) => k + ' 0 R').join(' ')}] /Count ${pageKids.length} >>`;
    const infoRef = addObject(`<< /Title (${escapePdf(encodeText('Informe de seguridad SOC'))}) /Author (${escapePdf(encodeText(metaAnalyst || 'Analista SOC'))}) /Creator (NODO SOC Analyzer) >>`);

    let output = '%PDF-1.4\n%\xe2\xe3\xcf\xd3\n';
    const offsets = [];
    objects.forEach((obj, i) => { offsets.push(output.length); output += `${i + 1} 0 obj\n${obj}\nendobj\n`; });
    const xrefStart = output.length;
    output += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n` + offsets.map((o) => String(o).padStart(10, '0') + ' 00000 n \n').join('');
    output += `trailer\n<< /Size ${objects.length + 1} /Root ${catalogRef} 0 R /Info ${infoRef} 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;

    const bytes = new Uint8Array(output.length);
    for (let i = 0; i < output.length; i++) bytes[i] = output.charCodeAt(i) & 0xff;
    return bytes;
  }

  global.PDFGenerator = { render: renderBlocks };
})(window);
