const filePicker = document.getElementById("filePicker");
const scanLocalBtn = document.getElementById("scanLocal");
const dropZone = document.getElementById("dropZone");
const fileStatus = document.getElementById("fileStatus");

// ✅ Ensure Scan Local button enables when files are selected
filePicker.addEventListener("change", function (event) {
    updateFileList(event.target.files);
});

// ✅ Drag-and-Drop Event Listeners
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

    // ✅ Process dropped files
    const files = event.dataTransfer.files;
    if (files.length > 0) {
        filePicker.files = files; // ✅ Make sure it updates the file input field
        updateFileList(files);
    }
});

// ✅ Updates UI & Enables Scan Button
function updateFileList(files) {
    if (files.length > 0) {
        scanLocalBtn.disabled = false;
        let fileNames = Array.from(files).map(file => file.name).join(", ");
        fileStatus.textContent = `Selected files: ${fileNames}`;
    } else {
        scanLocalBtn.disabled = true;
        fileStatus.textContent = "No files selected.";
    }
}

// ✅ Scan Local Files
scanLocalBtn.addEventListener("click", async function () {
    const files = filePicker.files;
    if (files.length === 0) {
        alert("No files selected for scanning.");
        return;
    }

    document.getElementById("localResults").innerHTML = "<p>Scanning selected files...</p>";

    let vulnerabilityPatterns = await loadVulnerabilityPatterns();
    let vulnerableFiles = {};

    for (const file of files) {
        await readAndScanFile(file, vulnerabilityPatterns, vulnerableFiles);
    }

    displayScanResults(vulnerableFiles, "localResults");
});

// ✅ Reads File Content & Scans
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

// ✅ Scan File for Vulnerabilities
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

// ✅ Displays Scan Results
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
