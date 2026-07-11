#!/usr/bin/env node
const fs = require('fs');

const SECRET_PATTERNS = {
    "Generic API Key/Password": /(api_key|secret|password|token|credential|pwd)\s*[:=]\s*["']([A-Za-z0-9%_+./-]{8,})["']/i,
    "Slack Token": /xox[bapr]-[0-9]{12}-[A-Za-z0-9]{24}/,
    "AWS Access Key ID": /AKIA[0-9A-Z]{16}/,
    "GitHub Token": /ghp_[A-Za-z0-9_]{36}/,
    "Private Key Header": /-----BEGIN [A-Z]+ PRIVATE KEY-----/
};

function calculateEntropy(str) {
    if (!str) return 0;
    const frequencies = {};
    for (let char of str) {
        frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (let char in frequencies) {
        const p = frequencies[char] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

function scanFile(filePath) {
    let findings = [];
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split(/\r?\n/);

        lines.forEach((line, index) => {
            const lineNum = index + 1;

            for (let [name, pattern] of Object.entries(SECRET_PATTERNS)) {
                if (pattern.test(line)) {
                    findings.push(`❌ [MATCH] ${name} found in ${filePath} at line ${lineNum}\n   ↳ Content: ${line.trim()}`);
                }
            }

            const quoteRegex = /["']([A-Za-z0-9_+\/=.-]{12,})["']/g;
            let match;
            while ((match = quoteRegex.exec(line)) !== null) {
                const token = match[1];
                const entropy = calculateEntropy(token);
                if (entropy > 4.5) {
                    findings.push(`⚠️ [ENTROPY] High randomness string (${entropy.toFixed(2)}) found in ${filePath} at line ${lineNum}\n   ↳ Token: ${token}`);
                }
            }
        });
    } catch (e) {}
    return findings;
}

const filesToScan = process.argv.slice(2);
let allFindings = [];

filesToScan.forEach(file => {
    allFindings = allFindings.concat(scanFile(file));
});

if (allFindings.length > 0) {
    console.error("\n=== 🛑 SECURITY ALERT: Exposed Secrets Detected! ===");
    allFindings.forEach(finding => console.error(finding));
    console.error("===================================================\n");
    console.error("Commit blocked. Remove the secrets or bypass via 'git commit --no-verify'.\n");
    process.exit(1);
}

process.exit(0);
