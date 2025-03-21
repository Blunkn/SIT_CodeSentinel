import * as scanner from "./script.js";

// ========================== GITHUB REPO SCANNING ==========================

// GitHub Scan Button Event Listener
document.getElementById("scanBtn").addEventListener("click", async function () {
    const button = this;
    const spinner = button.querySelector(".spinner");
    button.disabled = true;
    spinner.style.display = "inline-block";
    document.getElementById("results").innerHTML = ""; // Clear previous results

    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        const url = new URL(tabs[0].url);
        const pathParts = url.pathname.split('/');

        if (pathParts.length < 3) {
            alert("Please open a valid GitHub repository page.");
            button.disabled = false;
            spinner.style.display = "none";
            return;
        }

        const user = pathParts[1];
        const repo = pathParts[2];

        try {
            await scanGitHubRepo(user, repo);
        } catch (error) {
            console.error("GitHub scan error:", error);
            document.getElementById("results").innerHTML = `<div class="alert alert-danger">Error during GitHub scan: ${error.message}</div>`;
        }

        button.disabled = false;
        spinner.style.display = "none";
    });
});

async function getDefaultBranch(user, repo) {
    const apiUrl = `https://api.github.com/repos/${user}/${repo}`;

    try {
        const response = await fetch(apiUrl);
        if (response.ok) {
            const data = await response.json();
            return data.default_branch;
        } else {
            console.error(`[ERROR] Failed to fetch default branch: ${response.status}`);
            return "main";
        }
    } catch (error) {
        console.error(`[ERROR] Error fetching default branch: ${error.message}`);
        return "main";
    }
}

// Fetch all files from GitHub repository
async function getAllFilesInRepo(user, repo, path = "") {
    const apiUrl = `https://api.github.com/repos/${user}/${repo}/contents/${path}`;

    try {
        const response = await fetch(apiUrl);
        if (!response.ok) {
            console.error(`[ERROR] Failed to fetch file list from ${path || "root"}: ${response.status}`);
            return [];
        }

        const data = await response.json();
        let files = [];

        for (const item of data) {
            if (item.type === "file") {
                files.push(item.path);
            } else if (item.type === "dir") {
                if (item.path.includes("node_modules")) continue; // Skip node_modules
                const subFiles = await getAllFilesInRepo(user, repo, item.path);
                files = files.concat(subFiles);
            }
        }

        return files;
    } catch (error) {
        console.error(`[ERROR] Error fetching repo file list: ${error.message}`);
        return [];
    }
}

// Scan GitHub repository files
async function scanGitHubRepo(user, repo) {
    const files = await getAllFilesInRepo(user, repo);
    const vulnerabilityPatterns = await loadVulnerabilityPatterns();
    let vulnerableFiles = {};

    for (const filePath of files) {
        const content = await getFileContentFromGitHub(user, repo, filePath);
        if (content) {
            let result = await scanFile(content, vulnerabilityPatterns, filePath); //Pass file path to scanfile
            if (filePath.endsWith(".js")) {
                if (result) {
                    result = result.concat(acornScan(content));
                }
                else {
                    result = acornScan(content);
                }
            }
            else if (filePath.endsWith(".html")) {
                const htmlVulns = scanHTMLCode(content);
                if (htmlVulns) {
                    result = result ? result.concat(htmlVulns) : htmlVulns;
                }

                const scripts = extractScriptsFromHTML(content);
                scripts.forEach(script => {
                    const scriptVulns = acornScan(script);
                    if (scriptVulns) {
                        result = result ? result.concat(scriptVulns) : scriptVulns;
                    }
                });
            }
            if (result) {
                vulnerableFiles[filePath] = result;
            }
        }
    }
    //Filter out files which do not contain files before displaying results
    const filteredVulnerableFiles = Object.fromEntries(
        Object.entries(vulnerableFiles).filter(([key, value]) => value !== null)
    );

    displayResults(filteredVulnerableFiles, "results");
}

// Fetch file content from GitHub
async function getFileContentFromGitHub(user, repo, filePath) {
    const defaultBranch = await getDefaultBranch(user, repo);
    const rawUrl = `https://raw.githubusercontent.com/${user}/${repo}/${defaultBranch}/${filePath}`;

    try {
        const response = await fetch(rawUrl);
        if (response.ok) {
            return await response.text();
        } else {
            console.error(`[ERROR] Failed to fetch ${filePath}: ${response.status}`);
            return null;
        }
    } catch (error) {
        console.error(`[ERROR] Error fetching file ${filePath}: ${error.message}`);
        return null;
    }
}

// ✅ Scan File for Vulnerabilities
async function scanFile(content, vulnerabilityPatterns, filename) {
    const vulnerabilities = [];

    vulnerabilityPatterns.forEach(({ pattern, description, severity }) => {
        const regex = new RegExp(pattern, "g");
        if (regex.test(content)) {
            vulnerabilities.push({ description, severity, pattern });
        }
    });
    if (filename.endsWith(".js")) {
        const acornVulns = acornScan(content);
        if (acornVulns) {
            vulnerabilities.concat(acornVulns);
        }
    }
    else if (filename.endsWith(".html")) {
        const htmlVulns = scanHTMLCode(content);
        if (htmlVulns) {
            vulnerabilities.concat(htmlVulns);
        }

        const scripts = extractScriptsFromHTML(content);
        scripts.forEach(script => {
            const scriptVulns = acornScan(script);
            if (scriptVulns) {
                vulnerabilities.concat(scriptVulns);
            }
        });
    }

    return vulnerabilities.length > 0 ? vulnerabilities : null;
}
// ✅ Load Vulnerability Patterns from JSON
async function loadVulnerabilityPatterns() {
    try {
        const response = await fetch("patterns.json");
        if (!response.ok) throw new Error(`Failed to load patterns.json: ${response.status}`);
        return await response.json();
    } catch (error) {
        console.error(`[ERROR] ${error.message}`);
        return [];
    }
}
// ✅ Displays Scan Results
// Reverted to the non XSS fix version
function displayResults(vulnerableFiles, resultContainerId) {
    const resultsDiv = document.getElementById(resultContainerId);
    resultsDiv.innerHTML = "";

    if (Object.keys(vulnerableFiles).length > 0) {
        resultsDiv.innerHTML = "<h3>Vulnerabilities Detected:</h3>";
        Object.entries(vulnerableFiles).forEach(([file, issues]) => {
          console.log("Issues:", issues); // ADDED DEBUGGING STATEMENT
            const fileElement = document.createElement("div");
            fileElement.classList.add("finding");
            fileElement.innerHTML = `<strong>${file}</strong>`;
            issues.forEach(({ description, severity, pattern }) => {
                fileElement.innerHTML += `
                    <div class="alert alert-danger">
                        <strong>${description}</strong> (Severity: ${severity})
                        <pre class="code-snippet">${pattern}</pre>
                    </div>
                `;
            });
            resultsDiv.appendChild(fileElement);
        });
    } else {
        resultsDiv.innerHTML = `<div class="alert alert-success">No vulnerabilities detected.</div>`;
    }
}

function acornScan(code) {
    return scanner.parseJSCode(code).length > 0 ? scanner.parseJSCode(code) : null;
}

function extractScriptsFromHTML(code) {
    const scriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
    let scripts = [];
    let match;

    while ((match = scriptRegex.exec(code)) !== null) {
        scripts.push(match[1]);
    }

    return scripts;
}

function scanHTMLCode(code) {
    const vulnerabilities = scanner.parseHTMLCode(code);
    return vulnerabilities.length > 0 ? vulnerabilities : null;
}