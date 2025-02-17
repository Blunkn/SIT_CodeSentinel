const fs = require("fs");
const path = require("path");

// Define Log4Shell patterns with severity ratings
const LOG4J_EXPLOITS = [
    { pattern: /\$\{jndi:ldap:\/\/.*?\}/g, description: "JNDI LDAP Injection - CVE-2021-44228", severity: "Critical" },
    { pattern: /\$\{jndi:rmi:\/\/.*?\}/g, description: "JNDI RMI Injection - CVE-2021-44228", severity: "Critical" },
    { pattern: /\$\{jndi:dns:\/\/.*?\}/g, description: "JNDI DNS Injection - CVE-2021-44228", severity: "High" },
    { pattern: /org\.apache\.logging\.log4j\.core\.lookup\.JndiLookup/g, description: "JndiLookup Class Usage (Log4Shell)", severity: "Critical" },
    { pattern: /logger\.error\(.*\$\{jndi:.*?\}.*\)/g, description: "Logging Unfiltered User Input - Possible RCE", severity: "Critical" },
    { pattern: /logger\.warn\(.*\$\{jndi:.*?\}.*\)/g, description: "Logging Unfiltered User Input - Possible RCE", severity: "Critical" },
    { pattern: /logger\.info\(.*\$\{jndi:.*?\}.*\)/g, description: "Logging Unfiltered User Input - Potential Vulnerability", severity: "High" },
    { pattern: /User-Agent: .*?\$\{jndi:.*?\}/g, description: "User-Agent Header Exploit (Log4Shell Attack)", severity: "Critical" },
    { pattern: /X-Forwarded-For: .*?\$\{jndi:.*?\}/g, description: "X-Forwarded-For Header Exploit (Log4Shell Attack)", severity: "Critical" },
];

function scanFile(filePath) {
    const vulnerabilities = [];
    try {
        const content = fs.readFileSync(filePath, "utf-8");
        LOG4J_EXPLOITS.forEach(({ pattern, description, severity }) => {
            if (pattern.test(content)) {
                vulnerabilities.push({ description, severity, pattern });
            }
        });
    } catch (error) {
        console.error(`[ERROR] Could not read ${filePath}: ${error.message}`);
        return null;
    }

    return vulnerabilities.length > 0 ? vulnerabilities : null;
}

function scanDirectory(directory) {
    const absolutePath = path.resolve(directory);
    if (!fs.existsSync(absolutePath)) {
        console.error(`[ERROR] Invalid directory path: ${absolutePath}`);
        return;
    }

    console.log(`\n🔍 Scanning directory: ${absolutePath} ...`);
    let vulnerableFiles = {};

    function scanRecursive(currentPath) {
        fs.readdirSync(currentPath).forEach((file) => {
            const filePath = path.join(currentPath, file);
            if (fs.statSync(filePath).isDirectory()) {
                scanRecursive(filePath);
            } else if (file.endsWith(".java") || file.endsWith(".log") || file.endsWith(".txt")) {
                const result = scanFile(filePath);
                if (result) {
                    vulnerableFiles[filePath] = result;
                }
            }
        });
    }

    scanRecursive(absolutePath);

    if (Object.keys(vulnerableFiles).length > 0) {
        console.log("\n⚠️  [Vulnerable Files Detected]");
        Object.entries(vulnerableFiles).forEach(([file, issues]) => {
            console.log(`\n📌 **${file}**`);
            issues.forEach(({ description, severity, pattern }) => {
                console.log(`   🔴 Vulnerability: ${description}`);
                console.log(`   🔥 Severity: ${severity}`);
                console.log(`   🔍 Detected Pattern: ${pattern}\n`);
            });
        });
    } else {
        console.log("\n✅ [INFO] No vulnerabilities detected.");
    }
}

// Run scanner
const targetDirectory = process.argv[2];
if (!targetDirectory) {
    console.error("\n[ERROR] Please provide a directory path to scan.");
    console.log("Usage: node log4j_scanner.js <directory_path>\n");
} else {
    scanDirectory(targetDirectory);
}
