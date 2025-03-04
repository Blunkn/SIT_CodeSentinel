// Get elements from the UI
const filePicker = document.getElementById("filePicker");
const scanLocalBtn = document.getElementById("scanLocal");
const dropZone = document.getElementById("dropZone");
const fileStatus = document.getElementById("fileStatus");

// Handle file selection via input
filePicker.addEventListener("change", function () {
    if (filePicker.files.length > 0) {
        scanLocalBtn.disabled = false;
        fileStatus.textContent = `Selected files: ${Array.from(filePicker.files).map(f => f.name).join(", ")}`;
    } else {
        scanLocalBtn.disabled = true;
        fileStatus.textContent = "No files selected";
    }
});

// Handle drag-and-drop functionality
dropZone.addEventListener("dragover", (event) => {
    event.preventDefault();
    dropZone.style.backgroundColor = "#e0efff";
});

dropZone.addEventListener("dragleave", () => {
    dropZone.style.backgroundColor = "";
});

dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    dropZone.style.backgroundColor = "";
    
    const files = event.dataTransfer.files;
    filePicker.files = files; // Attach files to input element
    scanLocalBtn.disabled = files.length === 0;
    fileStatus.textContent = files.length > 0 
        ? `Selected files: ${Array.from(files).map(f => f.name).join(", ")}` 
        : "No files selected";
});

// Local scanning process
scanLocalBtn.addEventListener("click", async function () {
    const files = filePicker.files;
    document.getElementById("localResults").innerHTML = "<p>Scanning selected files...</p>";

    let vulnerabilityPatterns = await loadVulnerabilityPatterns();
    let vulnerableFiles = {};

    for (const file of files) {
        await readAndScanFile(file, vulnerabilityPatterns, vulnerableFiles);
    }

    displayScanResults(vulnerableFiles, "localResults");
    detectPowerShellUsage(); // NEW: Detect running PowerShell
});

// Function to read file content and scan
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

// Function to scan file content
function scanFile(content, vulnerabilityPatterns) {
    const vulnerabilities = [];
    vulnerabilityPatterns.forEach(({ pattern, description, severity }) => {
        const regex = new RegExp(pattern, "g");
        if (regex.test(content)) {
            vulnerabilities.push({ description, severity, pattern });
        }
    });

    return vulnerabilities.length > 0 ? vulnerabilities : null;
}

// Function to display scan results
function displayScanResults(vulnerableFiles, resultContainerId) {
    const resultsDiv = document.getElementById(resultContainerId);
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
        resultsDiv.innerHTML = `<div class="alert alert-success">No vulnerabilities detected.</div>`;
    }
}

// Function to load vulnerability patterns from patterns.json
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

// ✅ NEW: Function to detect running PowerShell processes
function detectPowerShellUsage() {
    const command = navigator.userAgent.includes("Windows") ? "tasklist" : "ps aux";

    fetch("https://your-server-endpoint/check-processes", { // Placeholder for actual implementation
        method: "POST",
        body: JSON.stringify({ command: command }),
        headers: { "Content-Type": "application/json" }
    })
    .then(response => response.json())
    .then(data => {
        if (data.includes("powershell.exe") || data.includes("pwsh")) {
            document.getElementById("localResults").innerHTML += `
                <div class="alert alert-warning">
                    <strong>Warning:</strong> Running PowerShell process detected!
                </div>
            `;
        }
    })
    .catch(error => console.error("Error checking PowerShell processes:", error));
}
