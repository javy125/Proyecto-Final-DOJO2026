/**
 * Módulo de importación de datos de telemetría SIEM.
 * Soporta archivos .csv y .xlsx mediante lectura nativa del navegador.
 */
(function (global) {
  'use strict';

  const SEPARATORS = { comma: ',', semicolon: ';', tab: '\t', pipe: '|' };

  function detectDelimiter(sampleLine) {
    let best = SEPARATORS.comma;
    let maxCount = 0;
    for (const [name, sep] of Object.entries(SEPARATORS)) {
      const count = (sampleLine.match(new RegExp('\\' + sep, 'g')) || []).length;
      if (count > maxCount) { maxCount = count; best = sep; }
    }
    return best;
  }

  function parseCsvText(text) {
    const lines = text.split(/\r?\n/);
    if (lines.length === 0) return { headers: [], rows: [] };

    const headerLine = lines[0].replace(/^\uFEFF/, '');
    const delimiter = detectDelimiter(headerLine);
    const headers = headerLine.split(delimiter).map((h) => h.trim().replace(/^"|"$/g, ''));
    const rows = [];

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      const values = splitCsvLine(line, delimiter);
      const obj = {};
      headers.forEach((h, idx) => { obj[h] = values[idx] !== undefined ? values[idx] : ''; });
      rows.push(obj);
    }
    return { headers, rows };
  }

  function splitCsvLine(line, delimiter) {
    const values = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (inQuotes) {
        if (ch === '"') {
          if (i + 1 < line.length && line[i + 1] === '"') { current += '"'; i++; }
          else { inQuotes = false; }
        } else { current += ch; }
      } else {
        if (ch === '"') { inQuotes = true; }
        else if (ch === delimiter) { values.push(current); current = ''; }
        else { current += ch; }
      }
    }
    values.push(current);
    return values;
  }

  async function readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(new Error('No se pudo leer el archivo.'));
      reader.readAsText(file);
    });
  }

  async function readFileAsBuffer(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(new Error('No se pudo leer el archivo.'));
      reader.readAsArrayBuffer(file);
    });
  }

  function parseXlsxFromBuffer(buffer) {
    // Implementación mínima de lectura XLSX: lee el ZIP interno y extrae
    // la primera hoja de cálculo como filas de texto.
    const dataView = new DataView(buffer);
    const uint8 = new Uint8Array(buffer);

    function findEndOfCentralDirectory() {
      for (let i = uint8.length - 22; i >= Math.max(0, uint8.length - 65557); i--) {
        if (dataView.getUint32(i, true) === 0x06054b50) return i;
      }
      return -1;
    }

    const eocd = findEndOfCentralDirectory();
    if (eocd < 0) throw new Error('El archivo no es un XLSX válido (ZIP no reconocido).');

    const totalEntries = dataView.getUint16(eocd + 10, true);
    const centralDirOffset = dataView.getUint32(eocd + 16, true);
    const decoder = new TextDecoder();
    const entries = {};

    let ptr = centralDirOffset;
    for (let n = 0; n < totalEntries; n++) {
      if (dataView.getUint32(ptr, true) !== 0x02014b50) break;
      const method = dataView.getUint16(ptr + 10, true);
      const compressedSize = dataView.getUint32(ptr + 20, true);
      const nameLen = dataView.getUint16(ptr + 28, true);
      const extraLen = dataView.getUint16(ptr + 30, true);
      const commentLen = dataView.getUint16(ptr + 32, true);
      const localHeaderOffset = dataView.getUint32(ptr + 42, true);
      const name = decoder.decode(uint8.subarray(ptr + 46, ptr + 46 + nameLen));
      entries[name] = { method, compressedSize, localHeaderOffset };
      ptr += 46 + nameLen + extraLen + commentLen;
    }

    async function readEntry(name) {
      const entry = entries[name];
      if (!entry) return null;
      const dv = dataView;
      const u8 = uint8;
      const nameLenLocal = dv.getUint16(entry.localHeaderOffset + 26, true);
      const extraLenLocal = dv.getUint16(entry.localHeaderOffset + 28, true);
      const dataStart = entry.localHeaderOffset + 30 + nameLenLocal + extraLenLocal;
      const raw = u8.subarray(dataStart, dataStart + entry.compressedSize);
      if (entry.method === 0) return decoder.decode(raw);
      if (entry.method !== 8) throw new Error('Método de compresión ZIP no soportado: ' + entry.method);
      try {
        const stream = new Blob([raw]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
        return await new Response(stream).text();
      } catch (err) {
        throw new Error('Error descomprimiendo entrada ZIP: ' + name);
      }
    }

    async function buildRows() {
      const sheetXmlText = await readEntry('xl/worksheets/sheet1.xml');
      if (!sheetXmlText) throw new Error('No se encontró la hoja de cálculo dentro del archivo XLSX.');

      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(sheetXmlText, 'application/xml');
      const ns = '*';
      const rows = [];

      const rowElements = xmlDoc.getElementsByTagNameNS(ns, 'row');
      for (const rowEl of rowElements) {
        const cells = [];
        let autoCol = 0;
        for (const cellEl of rowEl.getElementsByTagNameNS(ns, 'c')) {
          const ref = cellEl.getAttribute('r');
          const colIdx = ref ? columnRefToIndex(ref) : autoCol;
          autoCol = colIdx + 1;
          const type = cellEl.getAttribute('t');
          const valEl = cellEl.getElementsByTagNameNS(ns, 'v')[0];
          let value = '';
          if (valEl) value = valEl.textContent || '';
          cells[colIdx] = value;
        }
        if (cells.some((c) => c !== undefined && c !== '')) rows.push(cells);
      }
      return rows;
    }

    function columnRefToIndex(ref) {
      const letters = ref.replace(/[0-9]/g, '');
      let n = 0;
      for (const ch of letters) n = n * 26 + (ch.charCodeAt(0) - 64);
      return n - 1;
    }

    return { buildRows };
  }

  global.LogImporter = {
    parseCsv: parseCsvText,
    readText: readFileAsText,
    readBuffer: readFileAsBuffer,
    parseXlsxBuffer: parseXlsxFromBuffer
  };
})(window);
