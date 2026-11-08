(function(window) {
    'use strict';

    function printReport(title, contentHtml) {
        const win = window.open('', '_blank');
        if (!win) return;

        win.document.write(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>${title}</title>
                <style>
                    body { font-family: Arial, sans-serif; padding: 25px; color: #222; }
                    h1 { color: #1c2541; border-bottom: 2px solid #1c2541; padding-bottom: 8px; }
                    table { width: 100%; border-collapse: collapse; margin-top: 15px; }
                    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; font-size: 12px; }
                    th { background: #1c2541; color: white; }
                    .card-box { background: #f0f4f8; padding: 15px; border-radius: 5px; margin-bottom: 15px; }
                </style>
            </head>
            <body>
                <h1>${title}</h1>
                ${contentHtml}
                <script>window.onload = function() { window.print(); };</script>
            </body>
            </html>
        `);
        win.document.close();
    }

    window.PDFExporter = { print: printReport };
})(window);
