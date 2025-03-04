document.getElementById("filePicker").addEventListener("change", function (event) {
    const files = event.target.files;
    document.getElementById("scanLocal").disabled = files.length === 0;
});

document.getElementById("scanLocal").addEventListener("click", async function () {
    const files = document.getElementById("filePicker").files;
    document.getElementById("localResults").innerHTML = "<p>Scanning selected files...</p>";

    let vulnerabilityPatterns = await loadVulnerabilityPatterns();
    let vulnerableFiles = {};

    for (const file of files) {
        await readAndScanFile(file, vulnerabilityPatterns, vulnerableFiles);
    }

    displayScanResults(vulnerableFiles, "localResults");
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
