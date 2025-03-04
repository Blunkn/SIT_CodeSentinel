const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");

// Define Log4Shell and PowerShell Exploit Patterns
const EXPLOIT_PATTERNS = [
    // Log4Shell Exploits
    { pattern: /\$\{jndi:ldap:\/\/.*?\}/g, description: "JNDI LDAP Injection - CVE-2021-44228", severity: "Critical" },
    { pattern: /\$\{jndi:rmi:\/\/.*?\}/g, description: "JNDI RMI Injection - CVE-2021-44228", severity: "Critical" },
    { pattern: /org\.apache\.logging\.log4j\.core\.lookup\.JndiLookup/g, description: "JndiLookup Class Usage (Log4Shell)", severity: "Critical" },
    { pattern: /logger\.error\(.*\$\{jndi:.*?\}.*\)/g, description: "Logging Unfiltered User Input - Possible RCE", severity: "Critical" },

    // PowerShell Exploit Patterns
    { pattern: /\bInvoke-WebRequest\b/g, description: "PowerShell Web Request (Potential Remote Download)", severity: "Warning" },
    { pattern: /\bStart-Process\b/g, description: "PowerShell Process Execution (Potential Malicious Execution)", severity: "Warning" },
    { pattern: /\bNew-Object\s+System\.Net\.WebClient\b/g, description: "PowerShell WebClient (Potential Malware Download)", severity: "Warning" },
    { pattern: /\b-EncodedCommand\b/g, description: "PowerShell Encoded Command Execution", severity: "Warning" },
    { pattern: /\bInvoke-Expression\b/g, description: "PowerShell Command Execution (Potential Remote Code Execution)", severity: "Warning" },
    { pattern: /\bSet-MpPreference\b/g, description: "PowerShell Modifying Windows Defender Settings", severity: "Warning" }
];

// Function to scan a file for vulnerabilities
function scanFile(filePath) {
    const vulnerabilities = [];
    try {
        const content = fs.readFileSync(filePath, "utf-8");
        EXPLOIT_PATTERNS.forEach(({ pattern, description, severity }) => {
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

// Function to scan all files in a directory
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
            } else if (file.endsWith(".java") || file.endsWith(".log") || file.endsWith(".txt") ||
                       file.endsWith(".ps1") || file.endsWith(".bat") || file.endsWith(".sh")) {
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
                const severityIndicator = severity === "Critical" ? "🔥" : "⚠️";
                console.log(`   ${severityIndicator} Vulnerability: ${description}`);
                console.log(`   📌 Severity: ${severity}`);
                console.log(`   🔍 Detected Pattern: ${pattern}\n`);
            });
        });
    } else {
        console.log("\n✅ [INFO] No vulnerabilities detected.");
    }
}

// Function to detect running PowerShell processes
function detectPowerShellUsage() {
    const command = process.platform === "win32" ? "tasklist" : "ps aux";
    exec(command, (error, stdout) => {
        if (error) {
            console.error(`[ERROR] Unable to check running processes: ${error.message}`);
            return;
        }

        const detectedProcesses = [];
        if (/powershell\.exe/i.test(stdout) || /pwsh/i.test(stdout)) {
            detectedProcesses.push("PowerShell Process Detected (powershell.exe / pwsh)");
        }

        // if (detectedProcesses.length > 0) {
        //     console.log("\n🚨 ALERT: PowerShell Activity Detected!");
        //     detectedProcesses.forEach((alert) => console.log(`⚠️  ${alert}`));
        // }
    });
}

// Run scanner and PowerShell detection
const targetDirectory = process.argv[2];
if (!targetDirectory) {
    console.error("\n[ERROR] Please provide a directory path to scan.");
    console.log("Usage: node logscanner.js <directory_path>\n");
} else {
    detectPowerShellUsage();
    scanDirectory(targetDirectory);
}
