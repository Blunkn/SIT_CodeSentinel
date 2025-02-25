import { parse } from 'acorn';
import * as walk from 'acorn-walk';

// script.js
// .json doesn't allow comments so i'm putting here for my own reference
// manifest_version - a google thing, needs to be 3 for value
// name - chrome shows this on extension list
// description - chrome web store and extension settings show this
// version - our own version we set for the extension
// action - defines that the extension does when on the toolbar
// permission - defines that chrome APIs will be used
// host_permissions - defines that URLs the chrome extension can access
// - blunkn

// SUSPICIOUS/MALICIOUS CODE SIGNATURES
// uses regex to filter for common malcode patterns
const SUSPICIOUS_PATTERNS = {
    // command injection
    shellCommands: {
        pattern: /(exec|spawn|fork)\s*\([^)]*(?:sh|bash|powershell|cmd)/i,
        description: "Potential command injection",
        severity: "high"
    },

    // data exfil
    dataExfiltration: {
        pattern: /(\.send\s*\(.*{.*}|fetch\s*\([^)]*{method:\s*['"]POST['"]|\.post\s*\()/i,
        description: "Potential data exfiltration",
        severity: "high"
    },

    // evals
    unsafeEval: {
        pattern: /eval\(|new\s+Function\(|setTimeout\s*\(\s*['"`][^)]+['"`]\s*\)/i,
        description: "Unsafe code execution",
        severity: "high"
    },

    // obfuscated code
    base64Strings: {
        pattern: /['"]([A-Za-z0-9+/]{50,}=[^'"]*)['"]/,
        description: "Suspicious encoded string",
        severity: "medium"
    },

    // cryptomining
    cryptoMining: {
        pattern: /CryptoNight|cryptonight|minerId|coinhive|webassembly\.instantiate/i,
        description: "Potential crypto mining",
        severity: "high"
    },

    // env access
    envAccess: {
        pattern: /process\.env|dotenv|require\(['"]env/i,
        description: "Environment variable access",
        severity: "medium"
    },

    // file ops
    fileOps: {
        pattern: /(?:\.(?:write|append)File|fs\.(?:write|append))/i,
        description: "Suspicious file operation",
        severity: "medium"
    }
};

// URL & TAB MANAGEMENT
// ps if anything consult chrome API docs & mozilla web docs
// get URL of current github tab
async function getURL() {
    // [tab] takes from the output of chrome.tabs.query API
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    // exception if tab isn't github
    if (!tab.url.includes('github.com')) {
        throw new Error('Please navigate to a GitHub repository');
    }
    return tab.url;
}

// parse URL; this takes from the getURL return value
function parseURL(url) {
    const match = url.match(/github\.com\/([^/]+)\/([^/]+)/); // match returns an array btw
    // exception if user is on github, but not specifically on a repo
    if (!match) {
        throw new Error('Invalid Github URL');
    }
    return {
        owner: match[1],
        repo: match[2]
    }
}

// use github's API to get a list of all files in the repo
// this takes from parseURL's return value
async function fetchRepo(owner, repo) {
    // recursively scrape the whole repo lmfao
    const response = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/main?recursive=1`);
    // exception if something goes wrong during fetching
    if (!response.ok) {
        throw new Error('Failed to fetch repository files');
    }
    const data = await response.json(); // read fetch return value as json
    return data.tree.filter(item => item.type === 'blob'); // this filters for the actual files
} // === means strict equality btw, i didn't know this lol

// path input comes from fetchrepo return value
async function scanFile(owner, repo, path) {
    const response = await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/${path}`);
    if (!response.ok) {
        throw new Error(`Failed to fetch file: ${path}`);
    }
    const data = await response.json();
    const content = atob(data.content); // atob means ascii to binary; github API returns stuff in base64
    return scanContent(content, path);
}

// the actual scanner
function scanContent(content, filepath) {
    const results = [];
    const lines = content.split('\n');

    // nested for loop; for every line of code, check against sus patterns iteratively
    // lineno is Line No. or Line Number
    lines.forEach((line, lineno) => {
        for (const [name, config] of Object.entries(SUSPICIOUS_PATTERNS)) {
            // if condition for regex matches
            if (config.pattern.test(line)) {
                results.push({
                    type: name,
                    description: config.description,
                    severity: config.severity,
                    line: lineno + 1,
                    snippet: line.trim()
                });
            }
        }
    });
    return results.length > 0 ? { filepath, results } : null; // ?: is shorthand if-else; if got stuff return them, else return null
}

// show scan results
function displayResults(results) {
    const resultsDiv = document.getElementById('results');
    // if scan didn't find anything
    if (results.length === 0) {
        resultsDiv.innerHTML = `
      <div class = "alert alert-success">
        No suspicious code detected
      </div>
    `;
        return;
    }
    const resultsHTML = results.map(result => `
    <div class="alert alert-warning">
      <strong>File: ${result.filePath}</strong>
      ${result.findings.map(finding => `
        <div class="finding">
          <div>${finding.description} (Line ${finding.line})</div>
          <div class="code-snippet">${finding.snippet}</div>
        </div>
      `).join('')}
    </div>
  `).join('');

    resultsDiv.innerHTML = resultsHTML;
}

// main
async function startScan() {
    // const scanBtn = document.getElementById('scanBtn');
    // const resultsDiv = document.getElementById('results');

    try {
        scanBtn.disabled = true;
        scanBtn.classList.add('scanning');
        resultsDiv.innerHTML = '<div class="alert alert-success">Scanning repository...</div>';

        const url = await getURL();
        const { owner, repo } = parseURL(url);
        const files = await fetchRepo(owner, repo);

        const scanResults = [];
        for (const file of files) {
            if (file.path.match(/\.(js|ts|jsx|tsx|py|php|rb)$/i)) {
                const result = await scanFile(owner, repo, file.path);
                if (result) {
                    scanResults.push(result);
                }
            }
        }

        displayResults(scanResults);
    } catch (error) {
        resultsDiv.innerHTML = `
      <div class="alert alert-danger">
        Error: ${error.message}
      </div>
    `;
    } finally {
        scanBtn.disabled = false;
        scanBtn.classList.remove('scanning');
    }
}

// Wait for DOM to be ready before attaching event listeners
document.addEventListener('DOMContentLoaded', () => {
    //const scanBtn = document.getElementById('scanBtn');
    // Attach an event listener to the button
    // scanBtn.addEventListener('click', startScan);
});

// This function is called when the button is clicked
function myFunction() {
    alert('Button clicked! Testing, this is an alert function myFunction() that is triggered in the script.js file.');
}

export function parseJSCode(code) {
    try {
        const ast = parse(code, {
            ecmaVersion: "latest",
            locations: true,
            sourceType: "module"
        });
        const checks = getVulnerabilitiesChecks(code);
        walk.simple(ast, checks);
        return checks.vulnerabilities;
    } catch (error) {
        console.error("Error parsing JavaScript: ", error);
        return null;
    }
}

const getVulnerabilitiesChecks = (code) => {
    const userInputs = new Set();

    return {
        vulnerabilities: [],

        VariableDeclarator(node) {
            if (node.init && isUserInput(node.init)) {
                userInputs.add(node.id.name);
            }
        },

        AssignmentExpression(node) {
            if (
                node.left.type === "MemberExpression" &&
                (node.left.property.name === "innerHTML" ||
                    node.left.property.name === "outerHTML")
            ) {
                let isUnsafe = false;

                if (node.right.type === "Literal") {
                    const value = node.right.value;
                    if (/<script|onerror|onload|javascript:/i.test(value)) {
                        isUnsafe = true;
                    }
                }
                else if (node.right.type === "TemplateLiteral") {
                    if (node.right.expressions.length > 0) {
                        isUnsafe = true;
                    }
                }
                else if (node.right.type === "Identifier" && userInputs.has(node.right.name)) {
                    isUnsafe = true;
                }
                else {
                    isUnsafe = true;
                }

                if (isUnsafe) {
                    this.vulnerabilities.push({
                        pattern: getPattern(code, node),
                        description: `Potential XSS: Assigning to ${node.left.property.name}`,
                        severity: "Critical"
                    });
                }
            }
        },

        CallExpression(node) {
            // Detect document.write() usage
            if (
                node.callee.type === "MemberExpression" &&
                node.callee.object.name === "document" &&
                node.callee.property.name === "write"
            ) {
                this.vulnerabilities.push({
                    pattern: getPattern(code, node),
                    description: `Potential XSS: document.write() used`,
                    severity: "Critical"
                });
            }

            // Detect eval() usage
            if (node.callee.name === "eval") {
                this.vulnerabilities.push({
                    pattern: getPattern(code, node),
                    description: `Potential XSS: eval() used`,
                    severity: "Critical"
                });
            }
        }
    };
};

function getPattern(code, node) {
    return code.split("\n")[node.loc.start.line - 1].trim();
}

function isUserInput(node) {
    return (
        node.type === "CallExpression" &&
        (
            node.callee.name === "prompt" ||
            node.callee.name === "confirm" ||
            node.callee.name === "alert" ||
            (node.callee.object?.name === "document" && node.callee.property?.name === "getElementById")
        )
    );
}