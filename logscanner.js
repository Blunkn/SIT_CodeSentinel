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

        await scanGitHubRepo(user, repo);

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
            var result = await scanFile(content, vulnerabilityPatterns);
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

    displayResults(vulnerableFiles, "results");
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

// ========================== LOCAL FILE SCANNING ==========================

const filePicker = document.getElementById("filePicker");
const scanLocalBtn = document.getElementById("scanLocal");
const dropZone = document.getElementById("dropZone");
const fileStatus = document.getElementById("fileStatus");

// Enable scan button when files are selected
filePicker.addEventListener("change", function () {
    if (filePicker.files.length > 0) {
        scanLocalBtn.disabled = false;
        fileStatus.textContent = `${filePicker.files.length} file(s) selected`;
    } else {
        scanLocalBtn.disabled = true;
        fileStatus.textContent = "No files selected";
    }
});

// Drag & Drop Events
dropZone.addEventListener("dragover", function (event) {
    event.preventDefault();
    dropZone.classList.add("highlight");
});

dropZone.addEventListener("dragleave", function () {
    dropZone.classList.remove("highlight");
});

dropZone.addEventListener("drop", function (event) {
    event.preventDefault();
    dropZone.classList.remove("highlight");

    const files = event.dataTransfer.files;
    if (files.length > 0) {
        filePicker.files = files;
        updateFileList(files);
    }
});

// Updates UI & Enables Scan Button
function updateFileList(files) {
    if (files.length > 0) {
        scanLocalBtn.disabled = false;
        fileStatus.textContent = `${files.length} file(s) selected`;
    } else {
        scanLocalBtn.disabled = true;
        fileStatus.textContent = "No files selected.";
    }
}

// Scan Local Files (NOW SCANS ALL FILE TYPES)
scanLocalBtn.addEventListener("click", async function () {
    document.getElementById("localResults").innerHTML = "<p>Scanning selected files...</p>";

    const files = filePicker.files;
    if (files.length === 0) {
        alert("No files selected for scanning.");
        return;
    }

    let vulnerabilityPatterns = await loadVulnerabilityPatterns();
    let vulnerableFiles = {};

    for (const file of files) {
        await readAndScanFile(file, vulnerabilityPatterns, vulnerableFiles);
    }

    displayResults(vulnerableFiles, "localResults");
});

// Reads File Content & Scans (NO FILE TYPE RESTRICTIONS)
function readAndScanFile(file, vulnerabilityPatterns, vulnerableFiles) {
    return new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = function (event) {
            const content = event.target.result;
            const result = scanFile(content, vulnerabilityPatterns);
            if (result) {
                vulnerableFiles[file.name] = result;
            }
            resolve();
        };
        reader.readAsText(file);
    });
}

// ========================== COMMON SCAN FUNCTIONS ==========================

// Load Vulnerability Patterns from JSON
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

// Scan File for Vulnerabilities
async function scanFile(content, vulnerabilityPatterns) {
    const vulnerabilities = [];

    vulnerabilityPatterns.forEach(({ pattern, description, severity }) => {
        const regex = new RegExp(pattern, "g");
        if (regex.test(content)) {
            vulnerabilities.push({ description, severity, pattern });
        }
    });

    return vulnerabilities.length > 0 ? vulnerabilities : null;
}

// Display Scan Results
function displayResults(vulnerableFiles, resultContainerId) {
    const resultsDiv = document.getElementById(resultContainerId);
    resultsDiv.innerHTML = "";

    if (Object.keys(vulnerableFiles).length > 0) {
        resultsDiv.innerHTML = "<h3>Vulnerabilities Detected:</h3>";
        Object.entries(vulnerableFiles).forEach(([file, issues]) => {
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
        resultsDiv.innerHTML = `<div class="alert alert-success"> No vulnerabilities detected.</div>`;
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