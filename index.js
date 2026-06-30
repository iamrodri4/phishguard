const readline = require('readline');
const dns = require('dns').promises;
const fs = require('fs').promises;

// Palabras clave sospechosas comunes en enlaces de Phishing
const SUSPICIOUS_KEYWORDS = ['banco', 'login', 'secure', 'signin', 'verification', 'soporte', 'cuenta', 'update', 'free-cp', 'netflix'];

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function preguntar(query) {
    return new Promise(resolve => rl.question(query, resolve));
}

async function analizarURL() {
    console.log("\n========================================");
    console.log("🛡️  PHISHGUARD v1.0 - ANALIZADOR SIMPLE 🛡️");
    console.log("========================================\n");

    const urlInput = await preguntar("Introduce la URL sospechosa a analizar: ");
    rl.close();

    try {
        // Extraer el dominio limpio de la URL
        let urlClean = urlInput.replace(/^(^\w+:|^)\/\//, '');
        const domain = urlClean.split('/')[0];

        console.log(`\n[+] Analizando dominio: ${domain}...`);

        let score = 0;
        let razones = [];

        // 1. Análisis Heurístico Simple (Palabras clave)
        const domainLower = domain.toLowerCase();
        SUSPICIOUS_KEYWORDS.forEach(keyword => {
            if (domainLower.includes(keyword)) {
                score += 30;
                razones.push(`Contiene palabra clave sospechosa: "${keyword}"`);
            }
        });

        // 2. Revisar subdominios excesivos (típico de phishing)
        const subdomainsCount = domain.split('.').length;
        if (subdomainsCount > 3) {
            score += 20;
            razones.push(`Tiene demasiados subdominios (${subdomainsCount}), estructura sospechosa.`);
        }

        // 3. Resolución de DNS (Saber si el sitio existe y su IP)
        let ipAddress = 'Desconocida';
        try {
            const addresses = await dns.resolve4(domain);
            ipAddress = addresses[0];
            console.log(`[✔] Servidor activo en la IP: ${ipAddress}`);
        } catch (dnsErr) {
            score += 10;
            razones.push("No tiene registros DNS válidos o está caído temporalmente.");
        }

        // Determinar nivel de riesgo
        let riesgo = "BAJO";
        if (score >= 50) riesgo = "ALTO 🚨";
        else if (score >= 20) riesgo = "MEDIO ⚠️";

        // Mostrar Resultados en la consola
        console.log("\n====== RESULTADOS DEL ANÁLISIS ======");
        console.log(`NIVEL DE RIESGO: ${riesgo} (${score}/100 puntos)`);
        if (razones.length > 0) {
            console.log("\nRazones detectadas:");
            razones.forEach(r => console.log(` - ${r}`));
        } else {
            console.log("No se encontraron patrones sospechosos evidentes.");
        }

        // 4. Generar reporte automático simple en TXT
        const reportText = `REPORTE DE SEGURIDAD - PHISHGUARD\n` +
                           `URL Analizada: ${urlInput}\n` +
                           `Dominio: ${domain}\n` +
                           `IP Servidor: ${ipAddress}\n` +
                           `Nivel de Riesgo: ${riesgo}\n` +
                           `Puntuación: ${score}/100\n` +
                           `Detalles:\n${razones.map(r => ` - ${r}`).join('\n')}\n` +
                           `Fecha: ${new Date().toISOString()}\n`;

        await fs.writeFile('reporte_phishing.txt', reportText);
        console.log("\n[✔] Reporte técnico guardado en 'reporte_phishing.txt'");

    } catch (err) {
        console.error("\n[X] Error al procesar la URL. Asegúrate de que esté bien escrita.", err.message);
    }
}

analizarURL();