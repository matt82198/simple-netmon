#Requires -Version 5.1
# Registers NetMon as a scheduled task for the current user (AtLogon trigger).
# Run from the netmon\ directory, or the paths will resolve correctly regardless.

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$NetmonScript = Join-Path $ScriptDir "netmon.py"

# Resolve pythonw.exe via the py launcher first, fall back to PATH search
$PythonW = $null
try {
    $PythonW = & py -c "import sys,os; print(os.path.join(os.path.dirname(sys.executable),'pythonw.exe'))" 2>$null
    if ($PythonW -and -not (Test-Path $PythonW)) {
        $PythonW = $null
    }
} catch {
    $PythonW = $null
}

if (-not $PythonW) {
    $found = Get-Command pythonw.exe -ErrorAction SilentlyContinue
    if ($found) {
        $PythonW = $found.Source
    }
}

if (-not $PythonW) {
    Write-Error "Cannot locate pythonw.exe. Install Python via python.org and ensure the py launcher is available."
    exit 1
}

Write-Host "Using pythonw: $PythonW"
Write-Host "Script path:   $NetmonScript"

$Action = New-ScheduledTaskAction `
    -Execute $PythonW `
    -Argument "`"$NetmonScript`"" `
    -WorkingDirectory $ScriptDir

$Trigger = New-ScheduledTaskTrigger -AtLogOn

$Settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew

$Principal = New-ScheduledTaskPrincipal `
    -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -RunLevel Limited `
    -LogonType Interactive

Register-ScheduledTask `
    -TaskName "NetMon" `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -Principal $Principal `
    -Force | Out-Null

# ── Optional baseline training ────────────────────────────────────────────────
$trainChoice = Read-Host "Run 1-hour baseline training now? Observes normal traffic (Y/n)"
if ($trainChoice -eq '' -or $trainChoice -match '^[Yy]') {
    Write-Host ""
    Write-Host "[*] Starting baseline training (1 hour). Progress logged to netmon.log."
    Write-Host "    Press Ctrl+C to cancel and save partial baseline."
    Write-Host ""
    $PythonExe = $PythonW -replace 'pythonw\.exe$', 'python.exe'
    if (-not (Test-Path $PythonExe)) { $PythonExe = "py" }
    & $PythonExe "`"$NetmonScript`"" --train 3600
    Write-Host ""
    Write-Host "[+] Baseline training complete. baseline.json written to script directory."
}

Write-Host ""
Write-Host "NetMon scheduled task registered (AtLogon, current user, hidden/windowless)."
Write-Host ""
Write-Host "To start immediately without logging out:"
Write-Host "  Start-ScheduledTask -TaskName NetMon"
Write-Host ""
Write-Host "NOTE: For visibility into SYSTEM-owned connections, re-run this script"
Write-Host "      from an elevated (Administrator) prompt and change -RunLevel to Highest."
