param(
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][string]$TrustedCertificate,
    [ValidateRange(1260,7200)][int]$Duration = 1265
)
$ErrorActionPreference = 'Stop'
$taskLibrary = Split-Path -Parent $PSScriptRoot
$taskManifest = Join-Path $PSScriptRoot 'routes-live/Cargo.toml'
$taskCargo = Join-Path $env:USERPROFILE '.cargo/bin/cargo.exe'
$taskCert = (Resolve-Path -LiteralPath $TrustedCertificate).Path
if ($Server.Contains('"') -or $taskCert.Contains('"')) { throw 'Invalid argument' }
& $taskCargo build --manifest-path $taskManifest --locked --offline
if ($LASTEXITCODE -ne 0) { throw 'Diagnostic build failed' }
$taskExecutable = Join-Path $PSScriptRoot 'routes-live/target/debug/oc-routes-live.exe'
$taskReportDirectory = Join-Path $taskLibrary 'protocol/live'
New-Item -ItemType Directory -Path $taskReportDirectory -Force | Out-Null
$taskReport = Join-Path $taskReportDirectory ('routes-live-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.jsonl')
$taskUser = Read-Host 'Test VPN username'
$taskSecret = Read-Host 'Test VPN password (hidden; not saved)' -AsSecureString
if ($taskUser.Contains("`n") -or $taskUser.Contains("`r")) { throw 'Invalid username' }
$taskInfo = New-Object System.Diagnostics.ProcessStartInfo
$taskInfo.FileName = $taskExecutable
$taskInfo.Arguments = '"{0}" "{1}" {2}' -f $Server, $taskCert, $Duration
$taskInfo.WorkingDirectory = $taskLibrary
$taskInfo.UseShellExecute = $false
$taskInfo.CreateNoWindow = $true
$taskInfo.RedirectStandardInput = $true
$taskInfo.RedirectStandardOutput = $true
$taskInfo.RedirectStandardError = $true
$taskProcess = New-Object System.Diagnostics.Process
$taskProcess.StartInfo = $taskInfo
$taskPointer = [IntPtr]::Zero
try {
    $taskProcess.Start() | Out-Null
    $taskProcess.StandardInput.WriteLine($taskUser)
    $taskPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($taskSecret)
    $taskPlain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($taskPointer)
    if ($taskPlain.Contains("`n") -or $taskPlain.Contains("`r")) { throw 'Invalid password' }
    $taskProcess.StandardInput.WriteLine($taskPlain)
    $taskProcess.StandardInput.Close()
    $taskPlain = $null
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($taskPointer)
    $taskPointer = [IntPtr]::Zero
    $taskSecret.Dispose()
    Write-Host ('Report: ' + $taskReport)
    while (($taskLine = $taskProcess.StandardOutput.ReadLine()) -ne $null) {
        $taskLine | Add-Content -LiteralPath $taskReport -Encoding utf8
        Write-Host $taskLine
    }
    $taskProcess.WaitForExit()
    if ($taskProcess.ExitCode -ne 0) { throw 'Live diagnostic did not pass; see redacted report' }
} finally {
    if ($taskPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($taskPointer) }
    $taskPlain = $null
    if ($taskProcess.Id -and !$taskProcess.HasExited) { $taskProcess.Kill() }
    $taskProcess.Dispose()
}
