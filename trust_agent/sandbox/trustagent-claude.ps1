<#
.SYNOPSIS
  TrustAgent sandbox shim. Launches a CLI agent INSIDE the TrustAgent Docker
  sandbox (isolated network, forced-proxy egress, lifecycle hooks) instead of
  running it directly on the host.

.DESCRIPTION
  Alias `claude` to this script to make sandboxing transparent: typing `claude`
  in a repo then launches a boxed, guarded agent. Add to your PowerShell $PROFILE:

      function claude { & "<path>\trust_agent\sandbox\trustagent-claude.ps1" @args }

  (This shadows the real `claude` binary. To call the raw CLI, use:
      & (Get-Command claude -CommandType Application) ... )

.PARAMETER Repo
  Repository to mount into the sandbox (default: current directory). Must contain
  no symlinks (the launcher rejects them for safety).

.PARAMETER Keep
  Leave the sandbox running on exit instead of stopping it.

.PARAMETER SmokeTest
  Launch, query the guard, and stop -- skipping the interactive login/chat.
  Used to verify the wrapper without a live Claude login.
#>
[CmdletBinding()]
param(
    [string]$Repo = (Get-Location).Path,
    [int]$Port = 0,
    [switch]$Keep,
    [switch]$SmokeTest
)

$Airlock = (Resolve-Path (Join-Path $PSScriptRoot '..\airlock.py')).Path
$py = (Get-Command python).Source
function Invoke-Airlock { param([Parameter(ValueFromRemainingArguments)]$a) & $py $Airlock @a }

if ($Port -eq 0) { $Port = Get-Random -Minimum 8800 -Maximum 8899 }

Write-Host "[TrustAgent] Launching sandboxed agent for $Repo (guard on :$Port)..." -ForegroundColor Cyan
$out = Invoke-Airlock run --repo $Repo --port $Port --detach
$match = [regex]::Match(($out -join "`n"), 'Session:\s*(\S+)')
if (-not $match.Success) { Write-Error "Sandbox launch failed:`n$out"; return }
$session = $match.Groups[1].Value
Write-Host "[TrustAgent] Sandbox up. Session $session -- agent is isolated; all egress forced through the guard." -ForegroundColor Green

try {
    if ($SmokeTest) {
        Write-Host "[TrustAgent] Smoke test -- guard status:" -ForegroundColor Cyan
        Invoke-Airlock status $session
        return
    }
    Write-Host "[TrustAgent] Checking authentication inside the sandbox..." -ForegroundColor Cyan
    Invoke-Airlock auth-status $session
    Write-Host "[TrustAgent] Opening login (one-time per session); then dropping you into the agent." -ForegroundColor Cyan
    Invoke-Airlock login $session
    Invoke-Airlock chat $session
}
finally {
    if ($Keep) {
        Write-Host "[TrustAgent] Sandbox left running. Stop with: python `"$Airlock`" stop $session" -ForegroundColor Yellow
    } else {
        Write-Host "[TrustAgent] Stopping sandbox $session..." -ForegroundColor Cyan
        Invoke-Airlock stop $session
    }
}
