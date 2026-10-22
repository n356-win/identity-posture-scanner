<#
.SYNOPSIS
    Connects to Microsoft Graph with the least-privilege read-only scopes this lab needs.

.DESCRIPTION
    Run this once per PowerShell session, before any other script in this lab.

    Every scope requested here is READ-ONLY. That is a deliberate design decision and it is
    arguably the most important one in the whole tool. A security scanner that asks for write
    permissions gets refused by competent administrators - and they are right to refuse it.
    Asking for the minimum, and being able to explain exactly why you need each one, is what
    gets your tool installed instead of deleted.

.PARAMETER ShowDetail
    Also prints module versions. Useful when you are writing a TROUBLESHOOTING.md entry and
    need to record exactly what was installed when something broke.

.EXAMPLE
    .\00-Connect-Lab.ps1

.EXAMPLE
    .\00-Connect-Lab.ps1 -ShowDetail

.NOTES
    THE FOUR SCOPES, AND WHY EACH IS NEEDED
      Application.Read.All            Read app registrations and service principals. This is
                                      the core of the inventory - without it you see nothing.
      Directory.Read.All              Read directory objects, including the OWNER of each
                                      identity. Owners are the headline finding in Phase 3.
      AuditLog.Read.All               Read sign-in activity, which is how dormancy is
                                      detected. Optional - the tool degrades gracefully.
      RoleManagement.Read.Directory   Read directory role assignments, so you can tell when
                                      a service principal holds a privileged role.

    Document these four in your published README with exactly this reasoning. "Here is what
    this needs and why" costs you nothing and earns trust you cannot buy.
#>

[CmdletBinding()]
param(
    [switch]$ShowDetail,

    # OPTIONAL - a Microsoft Graph access token obtained elsewhere.
    #
    # Supply this and the interactive browser sign-in is skipped entirely. Everything AFTER
    # the connection still runs: the scope check, the report, the write-scope warning.
    #
    # CORRECTED 23 Oct 2026. An earlier version of this comment said 00b-Connect-Pipeline.ps1
    # "calls through to here". IT DOES NOT. 00b is fully self-contained - it does the OIDC
    # exchange and calls Connect-MgGraph itself. The pipeline does not need this file at all.
    #
    # WHAT THIS PARAMETER IS ACTUALLY FOR: running this script's verification against a
    # DELEGATED token you obtained some other way, without a browser prompt.
    #
    # IT WILL MISLEAD YOU WITH AN APP-ONLY TOKEN. Every check below reads $ctx.Scopes, which
    # is populated from the "scp" claim. An app-only token carries "roles" instead, so Scopes
    # comes back EMPTY and this script will report that every required permission is missing
    # on a token that is perfectly valid.
    #
    # That is exactly why 00b decodes the token itself and reads "roles" directly, rather than
    # reusing the logic in this file. Two authentication models, two claim names, two checks.
    [string]$AccessToken
)

# Stop on the first error rather than limping onward with a half-broken session.
# For a connection script this is what you want: a failed connect should not look like a
# successful one.
$ErrorActionPreference = 'Stop'


# =============================================================================
# THE SCOPES
# =============================================================================
# Defined in one place so there is a single source of truth. Later in the script we compare
# what we ASKED for against what we were actually GRANTED - those are not the same thing,
# because an administrator may have consented to only some of them.
$RequiredScopes = @(
    'Application.Read.All'
    'Directory.Read.All'
    'AuditLog.Read.All'
    'RoleManagement.Read.Directory'
)


# =============================================================================
# STEP 1 - Is the Graph module even installed?
# =============================================================================
# The full Microsoft.Graph module is enormous and slow to import. You only need two
# sub-modules for this lab, so we check for those specifically rather than the whole thing.
# Importing only what you need is noticeably faster and signals competence to anyone reading
# your code.
#
#   Microsoft.Graph.Authentication - provides Connect-MgGraph, Get-MgContext
#   Microsoft.Graph.Applications   - provides Get-MgApplication, Get-MgServicePrincipal
$needed = @('Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications')

foreach ($m in $needed) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        # Fail with an instruction, not just an error. Someone running this for the first
        # time should know exactly what to do next without searching.
        Write-Warning "Module '$m' is not installed. Install the Graph SDK with:"
        Write-Warning "    Install-Module Microsoft.Graph -Scope CurrentUser"
        throw "Missing required module: $m"
    }
}


# =============================================================================
# STEP 2 - Connect (or reuse an existing connection)
# =============================================================================
# Connect-MgGraph opens a browser sign-in. If you are already connected from earlier in the
# session there is no need to do it again - but you DO need to check that the existing
# connection has all four scopes. A session connected with only two scopes will fail
# confusingly later, in the middle of an inventory run, rather than here where it is obvious.

$existing = Get-MgContext -ErrorAction SilentlyContinue

if ($existing) {
    # Work out whether anything we need is missing from the current session.
    $missing = $RequiredScopes | Where-Object { $_ -notin $existing.Scopes }

    if (-not $missing) {
        Write-Host "Already connected with all required scopes." -ForegroundColor Green
    }
    else {
        # Reconnecting is cheap and avoids a confusing failure three scripts later.
        Write-Host "Connected, but missing: $($missing -join ', ')" -ForegroundColor Yellow
        Write-Host "Reconnecting with the full scope set..."
        Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
    }
}
elseif ($AccessToken) {
    # ---------------------------------------------------------------------------------
    # TOKEN PATH - non-interactive. NOT used by 00b-Connect-Pipeline.ps1.
    # ---------------------------------------------------------------------------------
    # CORRECTED 23 Oct 2026. This block previously claimed the pipeline routes through here.
    # It does not. 00b connects on its own.
    #
    # USE THIS ONLY WITH A DELEGATED TOKEN. The verification below reads $ctx.Scopes, which
    # comes from the "scp" claim. A client-credentials token is APP-ONLY: its permissions are
    # in "roles", there is no "scp" at all, and Scopes comes back EMPTY. Feed one in here and
    # this script will tell you every required permission is missing, on a token that works
    # perfectly.
    #
    # That is not a bug to fix. It is two authentication models with two claim names, and it
    # is precisely why 00b carries its own check instead of reusing this one.
    Write-Host "Connecting with a supplied access token (non-interactive)..." -ForegroundColor Cyan

    # The SDK changed this parameter to expect a SecureString at v2. Handle both, so the
    # script does not break on whichever version the runner happens to install.
    try {
        $secure = ConvertTo-SecureString $AccessToken -AsPlainText -Force
        Connect-MgGraph -AccessToken $secure -NoWelcome
    }
    catch {
        Write-Verbose "SecureString form rejected; retrying as a plain string (older SDK)."
        Connect-MgGraph -AccessToken $AccessToken -NoWelcome
    }
}
else {
    # -NoWelcome suppresses the SDK banner. Keeps script output clean and readable, which
    # matters when you are screenshotting this for WALKTHROUGH.md.
    Connect-MgGraph -Scopes $RequiredScopes -NoWelcome
}

# Re-read the context after connecting. If this is empty the connection genuinely failed,
# even if no exception was thrown.
$ctx = Get-MgContext
if (-not $ctx) { throw "Connection failed - no Graph context was established." }


# =============================================================================
# STEP 3 - Report what we actually got
# =============================================================================
# This is the part most scripts skip, and it is the part that saves you an hour of
# debugging. Asking for a scope and being GRANTED a scope are different events: if the
# tenant requires admin consent and you are not an admin, you will connect successfully
# with fewer permissions than you requested, and the failure will surface much later.

Write-Host ""
Write-Host "Connected." -ForegroundColor Green
Write-Host "  Tenant : $($ctx.TenantId)"
Write-Host "  Account: $($ctx.Account)"
Write-Host ""

$granted    = $ctx.Scopes | Sort-Object
$notGranted = $RequiredScopes | Where-Object { $_ -notin $granted }

Write-Host "Scopes:" -ForegroundColor Cyan
foreach ($s in ($RequiredScopes | Sort-Object)) {
    if ($s -in $granted) {
        Write-Host "  [ok]      $s" -ForegroundColor Green
    }
    else {
        Write-Host "  [MISSING] $s" -ForegroundColor Red
    }
}

if ($notGranted) {
    Write-Host ""
    Write-Warning "Some scopes were not granted - admin consent is probably required."
    Write-Warning "Scripts that depend on them will fail. That is expected behaviour, not a"
    Write-Warning "bug in your code. Note which ones, and record it in TROUBLESHOOTING.md."
}


# =============================================================================
# STEP 4 - Safety check: are we holding any WRITE permissions?
# =============================================================================
# This lab is read-only by design. If you ever see output from this block, something has
# gone wrong - most likely you connected as an account with standing admin rights, or an
# earlier script requested a write scope.
#
# WHY THIS MATTERS: the credibility of a security tool rests on it being obviously safe to
# run. Catching your own over-permissioning is both good practice and a good habit to
# demonstrate publicly.
$writeScopes = $granted | Where-Object { $_ -match 'ReadWrite|\.Write|FullControl' }

if ($writeScopes) {
    Write-Host ""
    Write-Warning "This session holds WRITE scopes: $($writeScopes -join ', ')"
    Write-Warning "This lab makes no changes, but consider reconnecting with a"
    Write-Warning "least-privilege account so the session matches the tool's intent."
}


# =============================================================================
# OPTIONAL - module versions, for troubleshooting notes
# =============================================================================
# Graph SDK behaviour changes between versions. When you hit a bug worth writing up, the
# version number is the first thing you will wish you had recorded.
if ($ShowDetail) {
    Write-Host ""
    Write-Host "Module versions:" -ForegroundColor Cyan
    Get-Module Microsoft.Graph* |
        Select-Object Name, Version |
        Sort-Object Name |
        Format-Table -AutoSize
}

Write-Host ""
Write-Host "Ready. Next: .\01-Get-NHIInventory.ps1" -ForegroundColor Cyan
