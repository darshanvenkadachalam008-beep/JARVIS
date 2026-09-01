<#
setup_autostart.ps1
====================
Registers jarvis_watchdog.py to launch automatically every time you log
into Windows — including after a cold boot — with no manual PowerShell
commands needed ever again.

WHY A SCHEDULED TASK, NOT A WINDOWS SERVICE:
jarvis_watchdog.py launches jarvis_service.pyw, which is a GUI tray app
that needs microphone, speaker, and desktop access. Windows Services run
in an isolated background session (Session 0) with no access to any of
that — a service could launch the process, but it would be broken/silent
once running (this is the exact same reason JARVISWatcherService, which
IS a proper service, never touches audio/GUI at all). A Scheduled Task
triggered "at logon" runs in your normal interactive session instead,
so everything works exactly like running it by hand — it just happens
automatically.

WHAT THIS SETS UP:
  - One Scheduled Task: "JARVIS Watchdog"
  - Trigger: at your logon, on any reboot
  - Action: pythonw.exe jarvis_watchdog.py (silent, no console window)
  - The watchdog then handles launching jarvis_service.pyw itself, and
    relaunching it if it ever crashes or hangs — nothing further needed.

USAGE:
  Right-click PowerShell -> Run as Administrator, then:
    cd "D:\Mark-XXXIX-OR-main\Mark-XXXIX-OR-main"
    ./setup_autostart.ps1

  Re-run any time (e.g. after moving the project folder) to update the
  registered paths.
#>

$ErrorActionPreference = "Stop"

$ProjectDir = $PSScriptRoot
$PythonwExe = Join-Path $ProjectDir "venv\Scripts\pythonw.exe"
$WatchdogPy = Join-Path $ProjectDir "jarvis_watchdog.py"
$TaskName   = "JARVIS Watchdog"

if (-not (Test-Path $PythonwExe)) {
    Write-Host "ERROR: $PythonwExe not found. Run this from the project root, or check your venv path." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $WatchdogPy)) {
    Write-Host "ERROR: $WatchdogPy not found." -ForegroundColor Red
    exit 1
}

Write-Host "Registering scheduled task '$TaskName'..."
Write-Host "  Python:   $PythonwExe"
Write-Host "  Script:   $WatchdogPy"
Write-Host "  Work dir: $ProjectDir"

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

$Action = New-ScheduledTaskAction `
    -Execute $PythonwExe `
    -Argument ('"' + $WatchdogPy + '"') `
    -WorkingDirectory $ProjectDir

$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 0)

$Principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType Interactive `
    -RunLevel Limited

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -Principal $Principal `
    -Description "Launches and supervises JARVIS (jarvis_service.pyw) — auto-starts at login, restarts it if it crashes or hangs." `
    | Out-Null

Write-Host ""
Write-Host "Done. '$TaskName' is now registered." -ForegroundColor Green
Write-Host "It will fire automatically the next time you log in (including after a reboot)."
Write-Host ""
Write-Host "To test right now without rebooting:"
Write-Host "  Start-ScheduledTask -TaskName `"$TaskName`""
Write-Host ""
Write-Host "To check its status any time:"
Write-Host "  Get-ScheduledTask -TaskName `"$TaskName`" | Get-ScheduledTaskInfo"
