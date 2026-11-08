<#
.SYNOPSIS
  TrustAgent auto-sandbox wrapper for Claude Code (gateway-mediated control plane).

.DESCRIPTION
  Dot-source this from your PowerShell $PROFILE:

      . "C:\...\trust_agent\sandbox\trustagent-claude.ps1"

  Then every time you type `claude`, the session is automatically placed inside
  the TrustAgent sandbox: the wrapper ensures the decision gateway is running and
  the global hooks are installed, so EVERY tool action the agent takes is routed
  through the guard (ALLOW / BLOCK / STOP) before it executes. No manual setup.

  This is a control-plane sandbox (gateway mediation), not OS-level isolation:
  the agent runs on the host but cannot take any tool action without the guard's
  approval. If the gateway is unreachable the hooks fail CLOSED (all actions
  blocked), so a broken gateway can never silently un-sandbox a session.

  To launch the raw CLI without the sandbox (e.g. when developing TrustAgent
  itself, to avoid self-mediating your build session):

      $env:TRUSTAGENT_BYPASS = '1'; claude     # one session
      Remove-Item Env:\TRUSTAGENT_BYPASS        # re-enable the sandbox
#>

$script:TrustAgentSandboxRoot = $PSScriptRoot
$script:TrustAgentGateway = (Join-Path $PSScriptRoot '..\gateway\app\service.py')
$script:TrustAgentHealth  = 'http://127.0.0.1:8787/health'

function Test-TrustAgentGateway {
    try { Invoke-RestMethod $script:TrustAgentHealth -TimeoutSec 1 -ErrorAction Stop | Out-Null; return $true }
    catch { return $false }
}

function Start-TrustAgentGateway {
    if (Test-TrustAgentGateway) { return $true }
    $py = (Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if (-not $py) { Write-Warning '[TrustAgent] python not found; cannot start the gateway.'; return $false }
    Start-Process $py -ArgumentList "`"$script:TrustAgentGateway`"" -WindowStyle Hidden | Out-Null
    for ($i = 0; $i -lt 20; $i++) { Start-Sleep -Milliseconds 300; if (Test-TrustAgentGateway) { return $true } }
    Write-Warning '[TrustAgent] gateway did not come up; sessions will fail closed (all actions blocked).'
    return $false
}

function Install-TrustAgentHooks {
    $settings = Join-Path $HOME '.claude\settings.json'
    $hasHook = (Test-Path $settings) -and (Select-String -Path $settings -Pattern 'hook\.py' -Quiet)
    if (-not $hasHook) {
        $py = (Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
        if ($py) { & $py (Join-Path $script:TrustAgentSandboxRoot 'install_hooks.py') $HOME | Out-Null }
    }
}

function claude {
    # Resolve the REAL claude executable (Application, never this function -> no recursion).
    $real = (Get-Command claude -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if (-not $real) { Write-Error '[TrustAgent] claude executable not found on PATH.'; return }

    if ($env:TRUSTAGENT_BYPASS -eq '1') { & $real @args; return }

    Install-TrustAgentHooks
    [void](Start-TrustAgentGateway)
    Write-Host '[TrustAgent] session sandboxed - every tool action routes through the guard. ($env:TRUSTAGENT_BYPASS=1 to disable)' -ForegroundColor DarkCyan
    & $real @args
}
