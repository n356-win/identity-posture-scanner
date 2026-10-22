<#
.SYNOPSIS
    Connects to Microsoft Graph from a GitHub Actions runner using workload identity
    federation. No client secret, no certificate, nothing stored anywhere.

.DESCRIPTION
    The pipeline equivalent of 00-Connect-Lab.ps1. Same job - connect, then PROVE what you
    actually got - but with a completely different authentication model, and the difference
    matters enough to be worth stating before you read the code.

      00-Connect-Lab.ps1   interactive, DELEGATED. A human signs in. Effective access is the
                           INTERSECTION of what the app may ask for and what that human can
                           already do. The user's own role is a ceiling.

      00b (this script)    non-interactive, APP-ONLY. There is no human, so THERE IS NO
                           CEILING. Application permissions are absolute: Directory.Read.All
                           reads the entire directory, bounded by nothing.

    That is why this script refuses to continue if it is holding any write permission. In the
    interactive script a write scope is a warning, because the signed-in user's role still
    limits the damage. Here nothing limits it, so a write permission is a hard stop.

    THE EXCHANGE, in four moves:
      1. GitHub mints a short-lived OIDC token describing the run - repo, branch, workflow.
      2. This script presents that token to Entra as a CLIENT ASSERTION.
      3. Entra verifies GitHub's signature, the audience, and the SUBJECT against the
         federated credential you configured. All three must match.
      4. Entra returns a Graph access token. Lives about an hour. Nothing persists.

    No secret exists at any point. The proof of identity is a signed statement about the run,
    not a string someone could copy.

.PARAMETER ClientId
    Application (client) ID of the app registration carrying the federated credential.
    Not a secret - it is an identifier. Store it as a repo VARIABLE, not a repo secret.

.PARAMETER TenantId
    Directory (tenant) ID. Also not a secret.

.PARAMETER RequiredRoles
    Application permissions this run must hold. Defaults match 00-Connect-Lab.ps1.

    NOTE THE WORD "ROLES". In app-only these are APPLICATION permissions and they arrive in
    the token's "roles" claim. In delegated they are SCOPES and arrive in "scp". Same names,
    different claim, different object in the directory - appRoleAssignments rather than
    oauth2PermissionGrants. Granting the delegated version and expecting this to work is the
    single most common failure here, and it fails with a 403 that says nothing useful.

.PARAMETER AllowWritePermissions
    Override the hard stop on write permissions. Do not use it. It exists so the refusal is a
    deliberate decision rather than something you work around by editing the script.

.EXAMPLE
    ./00b-Connect-Pipeline.ps1 -ClientId $env:AZURE_CLIENT_ID -TenantId $env:AZURE_TENANT_ID

.NOTES
    PREREQUISITES IN ENTRA - the federated credential alone is NOT enough.

    Authentication and authorization are separate problems and the credential only solves the
    first. Without the permissions below you will authenticate perfectly and then 403 on every
    call.

      1. App registration -> API permissions -> Microsoft Graph -> APPLICATION permissions
         (NOT delegated):
             Application.Read.All
             Directory.Read.All
             AuditLog.Read.All
             RoleManagement.Read.Directory

      2. Grant admin consent. All four require it. Until consent is granted they are
         REQUESTED, not GRANTED, and the distinction is invisible unless you look.

      3. Certificates & secrets -> Federated credentials -> Add:
             Issuer    https://token.actions.githubusercontent.com
             Subject   repo:OWNER/REPO:environment:lab
             Audience  api://AzureADTokenExchange

         The SUBJECT is the whole control. repo:OWNER/REPO:ref:refs/heads/* means any branch
         can assume this identity, and nothing about that looks wrong in a log.

    THIS SCRIPT HAS NEVER BEEN RUN. Like everything else in this folder it was written without
    a runner to test against. Expect to fix something. Write down what.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$TenantId,

    [string[]]$RequiredRoles = @(
        'Application.Read.All'
        'Directory.Read.All'
        'AuditLog.Read.All'
        'RoleManagement.Read.Directory'
    ),

    [switch]$AllowWritePermissions
)

$ErrorActionPreference = 'Stop'

# Entra's fixed audience for federated credential exchange. Not a URL that resolves - it is
# an identifier, and it must match the Audience field on the federated credential exactly.
$ExchangeAudience = 'api://AzureADTokenExchange'


function Write-Step { param([string]$Text) Write-Host "`n$Text" -ForegroundColor Cyan }


function ConvertFrom-JwtPayload {
    <#  Decodes a JWT's payload LOCALLY so we can read what Entra actually issued.

        Why decode at all: Get-MgContext does not reliably report application permissions when
        you connect with -AccessToken. The token itself is authoritative - it is literally the
        thing Entra signed - so we read it directly rather than asking the SDK what it thinks.

        LOCALLY is the operative word. An access token is a live credential for its lifetime.
        Never paste one into an online decoder; that is handing a working key to a stranger.
        This is three lines of base64 and does not leave the machine.                        #>
    param([Parameter(Mandatory)][string]$Token)

    $payload = $Token.Split('.')[1]

    # Base64URL -> Base64: different alphabet, and the padding is stripped. Put both back.
    $payload = $payload.Replace('-', '+').Replace('_', '/')
    switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '=' }
    }

    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload)) |
        ConvertFrom-Json
}


# #############################################################################
#  STEP 1 - Ask GitHub to vouch for this run
# #############################################################################
#  GitHub injects these two variables ONLY when the workflow declares:
#
#      permissions:
#        id-token: write
#
#  Missing variables almost always means that block is missing from the workflow, not that
#  anything is broken. It is the single most common setup mistake, so the message says so.
Write-Step 'Requesting OIDC token from GitHub...'

if (-not $env:ACTIONS_ID_TOKEN_REQUEST_URL -or -not $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN) {
    throw @"
No GitHub OIDC environment variables found.

If you are running inside GitHub Actions, the workflow is missing:

    permissions:
      id-token: write

Without it GitHub will not mint an OIDC token and these variables are never injected.
If you are running locally, use 00-Connect-Lab.ps1 instead - this script is pipeline-only.
"@
}

$githubToken = (Invoke-RestMethod `
    -Uri "$($env:ACTIONS_ID_TOKEN_REQUEST_URL)&audience=$ExchangeAudience" `
    -Headers @{ Authorization = "Bearer $($env:ACTIONS_ID_TOKEN_REQUEST_TOKEN)" }
).value

if (-not $githubToken) { throw 'GitHub returned no OIDC token.' }

# Mask immediately. GitHub scrubs masked values from logs even if a later step fails or a
# stack trace prints. Do this before the value can reach any other output.
Write-Host "::add-mask::$githubToken"

# Show the claims Entra is about to check. This is the most useful diagnostic in the script:
# when the exchange fails, the mismatch is almost always visible right here.
$ghClaims = ConvertFrom-JwtPayload -Token $githubToken
Write-Host '  GitHub asserts:'
Write-Host "    issuer     $($ghClaims.iss)"
Write-Host "    subject    $($ghClaims.sub)"      -ForegroundColor Yellow
Write-Host "    audience   $($ghClaims.aud)"
Write-Host '  The subject above must match the federated credential EXACTLY.' -ForegroundColor DarkGray


# #############################################################################
#  STEP 2 - Trade GitHub's statement for a Graph token
# #############################################################################
#  client_credentials with a JWT assertion instead of a secret. Entra fetches GitHub's public
#  signing keys, verifies the signature, then compares issuer, audience and subject against
#  the federated credential. Any mismatch and the whole exchange fails - there is no partial
#  success and no degraded mode.
Write-Step 'Exchanging for a Microsoft Graph token...'

$tokenBody = @{
    client_id             = $ClientId
    scope                 = 'https://graph.microsoft.com/.default'
    client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    client_assertion      = $githubToken
    grant_type            = 'client_credentials'
}

try {
    $tokenResponse = Invoke-RestMethod -Method POST `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body $tokenBody
}
catch {
    # Entra's error body names which check failed. It is genuinely informative and worth
    # surfacing in full rather than letting PowerShell's generic HTTP error hide it.
    $detail = $_.ErrorDetails.Message
    if (-not $detail) { $detail = $_.Exception.Message }

    throw @"
Token exchange failed.

$detail

Check, in this order - the first two account for nearly every failure:
  1. SUBJECT. Entra compared its configured subject against: $($ghClaims.sub)
  2. ISSUER.  Must be exactly https://token.actions.githubusercontent.com
  3. AUDIENCE on the federated credential must be $ExchangeAudience
  4. ClientId and TenantId are correct and the credential is on THAT app registration
"@
}

$graphToken = $tokenResponse.access_token
Write-Host "::add-mask::$graphToken"
Write-Host '  Token received.' -ForegroundColor Green


# #############################################################################
#  STEP 3 - Verify what you were actually given
# #############################################################################
#  ASKED FOR IS NOT THE SAME AS GOT. .default requests every application permission that has
#  been admin-consented - which means if consent was never granted, this succeeds and returns
#  a token with NO roles at all. That token authenticates perfectly and 403s on everything.
#
#  Failing here with a clear message beats failing in script 01 with an opaque 403.
Write-Step 'Verifying granted application permissions...'

$claims = ConvertFrom-JwtPayload -Token $graphToken
$granted = @($claims.roles)   # app-only: "roles". delegated would be "scp".

if ($granted.Count -eq 0) {
    throw @"
The token carries NO application permissions.

This is what an app registration looks like when permissions were ADDED but admin consent
was never GRANTED. The distinction is invisible in the portal unless you look at the Status
column - "Not granted for <tenant>" is the tell.

Fix: App registration -> API permissions -> Grant admin consent for <tenant>.
"@
}

$missing = $RequiredRoles | Where-Object { $_ -notin $granted }
$extra   = $granted       | Where-Object { $_ -notin $RequiredRoles }

foreach ($r in ($RequiredRoles | Sort-Object)) {
    if ($r -in $granted) { Write-Host "  [ok]      $r" -ForegroundColor Green }
    else                 { Write-Host "  [MISSING] $r" -ForegroundColor Red }
}
foreach ($r in ($extra | Sort-Object)) {
    # Not fatal, but worth naming. Scope creep on a pipeline identity is how a read-only
    # scanner quietly turns into something nobody reviewed.
    Write-Host "  [extra]   $r - granted but not required by this run" -ForegroundColor Yellow
}

if ($missing) {
    throw "Missing application permissions: $($missing -join ', '). Add them and grant admin consent."
}


# #############################################################################
#  STEP 4 - Refuse to run with write permissions. HARD STOP.
# #############################################################################
#  00-Connect-Lab.ps1 only WARNS about write scopes, and that is correct for interactive use:
#  a delegated token is still bounded by the signed-in user's role, so a stray write scope is
#  untidy rather than dangerous.
#
#  Here there is no user and no ceiling. An application write permission on an unattended
#  credential that runs on a schedule is exactly the finding this tool exists to report. The
#  tool refusing to hold one itself is not theatre - it is the only consistent position, and
#  it is a line worth being able to point at.
$writeRoles = $granted | Where-Object { $_ -match 'ReadWrite|\.Write|FullControl|\.All$' -and $_ -match 'ReadWrite|\.Write|FullControl' }

if ($writeRoles) {
    $msg = "This identity holds WRITE permissions: $($writeRoles -join ', ')"
    if ($AllowWritePermissions) {
        Write-Warning "$msg - continuing because -AllowWritePermissions was passed. Reconsider."
    }
    else {
        throw @"
$msg

Refusing to run. An unattended, scheduled credential with directory write access and no user
ceiling is the exact shape of finding this scanner reports. It should not describe the
scanner.

The blast radius of this credential should be a report, not a change.

Remove the write permissions, or pass -AllowWritePermissions if you have a reason you are
prepared to write down in TROUBLESHOOTING.md.
"@
    }
}


# #############################################################################
#  STEP 5 - Connect the SDK
# #############################################################################
Write-Step 'Connecting to Microsoft Graph...'

# The SDK changed this parameter to expect a SecureString at v2. If yours wants a plain
# string, drop the conversion - and note which version you are on in TROUBLESHOOTING.md,
# because this is the kind of thing that breaks a pipeline six months later.
$secureToken = ConvertTo-SecureString $graphToken -AsPlainText -Force
Connect-MgGraph -AccessToken $secureToken -NoWelcome

$ctx = Get-MgContext
if (-not $ctx) { throw 'Connect-MgGraph returned no context.' }

Write-Host ''
Write-Host 'Connected.' -ForegroundColor Green
Write-Host "  Tenant   : $($ctx.TenantId)"
Write-Host "  ClientId : $($ctx.ClientId)"
Write-Host "  AuthType : $($ctx.AuthType)"
Write-Host "  Roles    : $($granted.Count) application permission(s), all read-only"
Write-Host ''
Write-Host '  No secret was used or stored at any point in this run.' -ForegroundColor DarkGray
Write-Host ''
