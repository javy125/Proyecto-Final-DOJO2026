/**
 * Despachador de alertas por correo electrónico.
 * Genera un enlace mailto con el informe PDF adjunto como datos embebidos.
 * Expone: window.EmailDispatcher
 */
(function (global) {
  'use strict';

  async function send(recipient, subject, body, pdfBlob) {
    return new Promise((resolve, reject) => {
      try {
        const encodedSubject = encodeURIComponent(subject);
        const encodedBody = encodeURIComponent(body);
        let mailtoUrl = `mailto:${recipient}?subject=${encodedSubject}&body=${encodedBody}`;

        if (pdfBlob) {
          const reader = new FileReader();
          reader.onloadend = () => {
            const dataUrl = reader.result;
            mailtoUrl += `&attachment=${encodeURIComponent(dataUrl)}`;
            window.location.href = mailtoUrl;
            resolve({ success: true, message: `Cliente de correo abierto para ${recipient}` });
          };
          reader.onerror = () => reject(new Error('No se pudo leer el archivo PDF para adjuntar.'));
          reader.readAsDataURL(pdfBlob);
        } else {
          window.location.href = mailtoUrl;
          resolve({ success: true, message: `Cliente de correo abierto para ${recipient}` });
        }
      } catch (err) {
        reject(err);
      }
    });
  }

  global.EmailDispatcher = { send };
})(window);
