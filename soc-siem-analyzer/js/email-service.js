/**
 * Módulo para simular o despachar alertas por correo electrónico.
 */
(function(window) {
    'use strict';

    function sendAlertEmail(to, subject, body) {
        return new Promise((resolve) => {
            setTimeout(() => {
                console.log(`[EMAIL DISPATCH] Para: ${to} | Asunto: ${subject}`);
                resolve({ success: true, message: `Alerta enviada exitosamente a ${to}` });
            }, 600);
        });
    }

    window.EmailAlertService = { send: sendAlertEmail };
})(window);
