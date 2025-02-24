// Simulate Follina pattern in JavaScript
const follinaPayload = "msdt.exe /id PCWDiagnostic /skip force /force /c calc.exe";

// Function to scan for the pattern (mimics what your extension might do)
function scanForFollina(input) {
    const follinaRegex = /msdt\.exe\s*\/?\S*\s*\/.*?http[s]?:\/\//i;
    
    if (follinaRegex.test(input)) {
        console.log("⚠️ Vulnerability Detected: CVE-2022-30190 (Follina)");
    } else {
        console.log("✅ No vulnerabilities found.");
    }
}

// Test with the Follina exploit string
scanForFollina(follinaPayload);
