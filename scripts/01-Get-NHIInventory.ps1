<#
.SYNOPSIS
    Enumerates every non-human identity in the tenant - app registrations, service principals
    and managed identities - with their owners, credentials, permissions and sign-in activity.

.DESCRIPTION
    This is the core of v0.5. It is the PowerShell equivalent of azure_audit.py from the
    multi-cloud repo, extended with the things that script does not collect: owners,
    application permissions, and dormancy.

    READ-ONLY. This script makes no changes to the tenant.

    PERMISSION BOUNDARY - read this before running it anywhere but your own lab:
    unlike the v0.1 DNS checks, which only read public records and are safe to run against
    anyone, this script requires authenticated access to a tenant. Run it only against a
    tenant you own or have been explicitly asked to assess.

.PARAMETER OutputPath
    Where to write the inventory JSON. Default: ..\output\nhi_inventory.json

.PARAMETER SkipSignInActivity
    Skip the beta sign-in activity lookup. Use this if you do not hold AuditLog.Read.All.
    The script still works; you just lose dormancy detection.

.PARAMETER SkipPermissions
    Skip per-identity permission enumeration. Much faster, but you lose excessive-scope
    detection - which is the most valuable finding the tool produces. Use for a quick pass
    on a large tenant, not for a real assessment.

.EXAMPLE
    .\01-Get-NHIInventory.ps1

.EXAMPLE
    .\01-Get-NHIInventory.ps1 -SkipPermissions -Verbose
    Fast pass on a large tenant, with progress detail.

.NOTES
    BETA DEPENDENCY
    Sign-in activity comes from /beta/reports/servicePrincipalSignInActivities. Beta endpoints
    can change without notice. Declare this in your published README - shipping a tool that
    silently depends on beta and breaks later costs you the trust the tool was built to earn.

    PERFORMANCE
    Owner and permission lookups are one API call per identity. A tenant with 300 service
    principals therefore makes roughly 600 extra calls and can take several minutes. This is
    unavoidable with the Graph SDK; use -SkipPermissions when you just want a quick count.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\output\nhi_inventory.json'),
    [switch]$SkipSignInActivity,
    [switch]$SkipPermissions
)

$ErrorActionPreference = 'Stop'
$script:StartTime = Get-Date

# Fail immediately and clearly if the session is not connected, rather than producing a
# confusing authentication error 200 lines later.
if (-not (Get-MgContext)) { throw "Not connected. Run .\00-Connect-Lab.ps1 first." }

# Create the output directory if it does not exist yet.
$outDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }


# #############################################################################
#  BACKGROUND - the three classes of non-human identity
# #############################################################################
#
#  Getting this distinction right is the difference between a useful inventory and a
#  meaningless one. Most people conflate the first two and produce nonsense.
#
#  APP REGISTRATION  (Graph type: application)
#     The DEFINITION of an application. It lives in YOUR tenant. It is where client secrets
#     and certificates are configured. When someone says "rotate the credential", this is
#     the object they mean.
#
#  SERVICE PRINCIPAL (Graph type: servicePrincipal)
#     The INSTANCE of an application inside a tenant. Every app registration has one. But so
#     does every Microsoft first-party app and every third-party SaaS product anyone in your
#     tenant has ever consented to. A typical tenant has 150-400 of these and most are NOT
#     yours.
#
#  MANAGED IDENTITY  (a servicePrincipal with servicePrincipalType = 'ManagedIdentity')
#     An Azure-managed service principal. Crucially: it has NO rotatable secret. Azure
#     handles its credentials entirely. A tool that flags managed identities for credential
#     rotation tells an experienced administrator immediately that you do not understand the
#     platform - so we exclude them from all credential findings.
#
# #############################################################################


# =============================================================================
# STEP 1 - App registrations (the definitions, owned by this tenant)
# =============================================================================
# -All makes the SDK follow pagination for you. Without it you get only the first page
# (usually 100 objects) and would silently under-report on any real tenant.
#
# -Property limits which fields Graph returns. This is not just tidiness: requesting fewer
# properties is measurably faster, and some properties are not returned at all unless you
# ask for them explicitly.
Write-Host "[1/5] Reading app registrations..." -ForegroundColor Cyan

$apps = Get-MgApplication -All -Property @(
    'id'                      # the object ID in this tenant
    'appId'                   # the GLOBAL application ID - this is the join key to service principals
    'displayName'
    'createdDateTime'
    'signInAudience'          # single tenant, multi-tenant, or personal accounts
    'passwordCredentials'     # client secrets
    'keyCredentials'          # certificates
    'requiredResourceAccess'  # permissions the app has REQUESTED (not necessarily granted)
)

Write-Host "      $($apps.Count) app registrations"


# =============================================================================
# STEP 2 - Service principals (the instances - includes Microsoft and third parties)
# =============================================================================
Write-Host "[2/5] Reading service principals..." -ForegroundColor Cyan

$sps = Get-MgServicePrincipal -All -Property @(
    'id'
    'appId'
    'displayName'
    'servicePrincipalType'    # 'Application' | 'ManagedIdentity' | 'Legacy' | 'SocialIdp'
    'accountEnabled'
    'createdDateTime'
    'passwordCredentials'
    'keyCredentials'
    'appOwnerOrganizationId'  # which tenant owns the underlying app - useful for spotting Microsoft
    'tags'
)

Write-Host "      $($sps.Count) service principals"

# -----------------------------------------------------------------------------
# THE DISTINCTION THAT MAKES THE INVENTORY CREDIBLE
# -----------------------------------------------------------------------------
# Which of these service principals do WE actually own?
#
# A service principal is tenant-owned if its appId matches one of our own app registrations.
# Everything else is Microsoft first-party (Office, Teams, Defender...) or a third-party SaaS
# product someone consented to.
#
# WHY THIS MATTERS: reporting all 300 service principals as findings is the single mistake
# that makes NHI tools get ignored. 170 of them being Microsoft's is not a finding. We still
# inventory them - you want the complete picture - but we classify them separately and never
# flag them for owner assignment.
#
# A HashSet is used rather than a plain array because we do hundreds of lookups against it;
# HashSet lookup is constant time, array lookup is not.
$ownedAppIds = [System.Collections.Generic.HashSet[string]]::new()
foreach ($a in $apps) {
    if ($a.AppId) { [void]$ownedAppIds.Add($a.AppId) }   # [void] suppresses the True/False that Add returns
}

# Print a breakdown by type. This single line of output is worth screenshotting for
# WALKTHROUGH.md - it is the first moment the tenant's real shape becomes visible.
$byType = $sps | Group-Object ServicePrincipalType | Sort-Object Count -Descending
foreach ($g in $byType) { Write-Host ("      {0,-20} {1}" -f $g.Name, $g.Count) }


# =============================================================================
# STEP 3 - Sign-in activity (BETA) - this is how dormancy is detected
# =============================================================================
# GOTCHA WORTH KNOWING: service principal sign-in activity is NOT a property of the
# servicePrincipal object. You cannot get it from Get-MgServicePrincipal no matter which
# properties you request. It lives in a completely separate beta report.
#
# This trips up almost everyone the first time.
$signInMap = @{}   # keyed by appId, so we can join it back to each service principal

if (-not $SkipSignInActivity) {
    Write-Host "[3/5] Reading sign-in activity (beta)..." -ForegroundColor Cyan
    try {
        $uri = 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities'
        $page = 0

        # Manual pagination. Invoke-MgGraphRequest is a raw REST call, so unlike the
        # Get-Mg* cmdlets it does NOT follow @odata.nextLink for you. You must loop.
        # This is exactly the `while response is not None` loop in azure_audit.py.
        while ($uri) {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $uri

            foreach ($r in $resp.value) {
                if ($r.appId) { $signInMap[$r.appId] = $r }
            }

            # When there are no more pages, @odata.nextLink is absent and the loop ends.
            $uri = $resp.'@odata.nextLink'
            $page++
            Write-Verbose "  page $page, $($signInMap.Count) records so far"
        }

        Write-Host "      $($signInMap.Count) sign-in activity records"
    }
    catch {
        # Degrade gracefully rather than failing the whole run. Missing AuditLog.Read.All is
        # a common, recoverable situation - the rest of the inventory is still valuable.
        Write-Warning "Sign-in activity unavailable: $($_.Exception.Message)"
        Write-Warning "Dormancy detection will be degraded. This needs AuditLog.Read.All."
        Write-Warning "Worth a TROUBLESHOOTING.md entry if this is the first time you hit it."
    }
}
else {
    Write-Host "[3/5] Skipping sign-in activity (-SkipSignInActivity)" -ForegroundColor DarkGray
}


# #############################################################################
#  HELPER FUNCTIONS
# #############################################################################
#  Each does exactly one thing. That is the single-responsibility discipline the source repo
#  applies at the script level, applied here at the function level.
# #############################################################################

function Get-CredentialSummary {
    <#
        Normalises a set of password or certificate credentials into a consistent shape and
        works out the expiry state of each.

        Returns an empty set for managed identities - the caller skips them entirely, because
        a managed identity has no credential an administrator can rotate.
    #>
    param($Credentials, [string]$Kind)

    $now = (Get-Date).ToUniversalTime()   # always compare UTC to UTC; Graph returns UTC
    $out = @()

    foreach ($c in @($Credentials)) {     # @() guards against $null and single-item collections
        if (-not $c) { continue }

        $end = $null
        if ($c.EndDateTime) { $end = [datetime]$c.EndDateTime }

        $daysLeft = $null
        $expired  = $null

        if ($end) {
            # Negative DaysLeft means it expired that many days ago.
            $daysLeft = [int]($end.ToUniversalTime() - $now).TotalDays
            $expired  = $end.ToUniversalTime() -lt $now
        }

        $out += [pscustomobject]@{
            Kind        = $Kind                 # 'Password' or 'Certificate'
            KeyId       = [string]$c.KeyId
            DisplayName = $c.DisplayName
            StartDate   = if ($c.StartDateTime) { ([datetime]$c.StartDateTime).ToString('o') } else { $null }
            EndDate     = if ($end) { $end.ToString('o') } else { $null }
            DaysLeft    = $daysLeft
            Expired     = $expired
            NoExpiry    = ($null -eq $end)      # a credential with no end date at all - a real finding
        }
    }
    return $out
}


function Get-OwnerSummary {
    <#
        Retrieves the owners of a service principal or app registration.

        Ownership is THE headline finding of this tool. An identity with no owner is one
        nobody can attest to, nobody will notice being abused, and nobody will clean up.

        We capture AccountEnabled on each owner because an owner whose account is DISABLED is
        worse than no owner at all: the identity looks governed and is not.
    #>
    param(
        [string]$ObjectId,
        [ValidateSet('ServicePrincipal','Application')][string]$Type
    )

    try {
        $owners = if ($Type -eq 'ServicePrincipal') {
            Get-MgServicePrincipalOwner -ServicePrincipalId $ObjectId -All -ErrorAction Stop
        } else {
            Get-MgApplicationOwner -ApplicationId $ObjectId -All -ErrorAction Stop
        }

        $res = @()
        foreach ($o in @($owners)) {
            # Owners come back as generic directoryObject. The useful fields (displayName,
            # userPrincipalName, accountEnabled) are in AdditionalProperties rather than as
            # first-class properties - another Graph quirk worth knowing.
            $props = $o.AdditionalProperties

            $res += [pscustomobject]@{
                Id                = $o.Id
                DisplayName       = $props['displayName']
                UserPrincipalName = $props['userPrincipalName']
                AccountEnabled    = $props['accountEnabled']
                ObjectType        = $props['@odata.type']   # tells you user vs group vs SP
            }
        }
        return $res
    }
    catch {
        # A failed owner lookup should not abort the whole inventory - log it and move on.
        Write-Verbose "Owner lookup failed for $ObjectId : $($_.Exception.Message)"
        return @()
    }
}


function Get-AppRoleSummary {
    <#
        Retrieves APPLICATION permissions granted to a service principal.

        These are the permissions the identity holds in its own right, with no signed-in user
        involved - which makes them the ones that matter most. This is where excessive scope
        actually lives, and it is the hardest and most valuable part of v0.5.

        (Delegated permissions - oauth2PermissionGrants - act on behalf of a signed-in user
        and are a separate, generally lower-risk category.)
    #>
    param([string]$ServicePrincipalId)

    try {
        $grants = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalId -All -ErrorAction Stop

        $res = @()
        foreach ($g in @($grants)) {
            $res += [pscustomobject]@{
                ResourceDisplayName = $g.ResourceDisplayName   # e.g. "Microsoft Graph"
                ResourceId          = $g.ResourceId            # the resource SP's object ID
                AppRoleId           = [string]$g.AppRoleId     # a GUID - meaningless until resolved
            }
        }
        return $res
    }
    catch {
        Write-Verbose "App role lookup failed for $ServicePrincipalId"
        return @()
    }
}


# Resolving appRoleId GUIDs into readable permission names.
#
# Graph returns permissions as GUIDs. "Directory.ReadWrite.All" is actually
# 19dbc75e-c2e2-444c-a770-ec69d8559fc7 - unreadable, and useless for risk classification.
#
# To translate, you fetch the RESOURCE service principal (usually Microsoft Graph itself) and
# read its appRoles collection, which maps each GUID to a name.
#
# We cache aggressively because almost every grant resolves against the same handful of
# resources - without the cache this would be hundreds of redundant API calls.
$script:RoleNameCache = @{}

function Resolve-AppRoleName {
    param([string]$ResourceId, [string]$AppRoleId)

    if ([string]::IsNullOrWhiteSpace($ResourceId) -or [string]::IsNullOrWhiteSpace($AppRoleId)) { return $null }

    $key = "$ResourceId|$AppRoleId"
    if ($script:RoleNameCache.ContainsKey($key)) { return $script:RoleNameCache[$key] }

    try {
        # One call gets us EVERY role for this resource, so we cache them all at once.
        $resource = Get-MgServicePrincipal -ServicePrincipalId $ResourceId -Property 'appRoles' -ErrorAction Stop
        foreach ($r in @($resource.AppRoles)) {
            $script:RoleNameCache["$ResourceId|$($r.Id)"] = $r.Value
        }
    }
    catch {
        Write-Verbose "Could not resolve app roles for resource $ResourceId"
    }

    if ($script:RoleNameCache.ContainsKey($key)) { return $script:RoleNameCache[$key] }

    # Cache the miss too, so we do not retry a failing lookup on every subsequent identity.
    $script:RoleNameCache[$key] = $null
    return $null
}


# =============================================================================
# STEP 4 - Build the inventory
# =============================================================================
# This is the slow part: owners and permissions are one API call each, per identity.
Write-Host "[4/5] Building inventory (owners, permissions, dormancy)..." -ForegroundColor Cyan

# A generic List is used instead of += on an array. PowerShell arrays are immutable, so +=
# copies the entire array every time - fine for 10 items, painful for 400.
$inventory = [System.Collections.Generic.List[object]]::new()
$i = 0

foreach ($sp in $sps) {

    # Progress every 25 items rather than every item - Write-Progress is surprisingly
    # expensive and updating it constantly measurably slows the loop.
    $i++
    if ($i % 25 -eq 0) {
        Write-Progress -Activity "Enumerating identities" -Status "$i of $($sps.Count)" `
                       -PercentComplete (($i / [math]::Max($sps.Count,1)) * 100)
    }

    $isManagedIdentity = ($sp.ServicePrincipalType -eq 'ManagedIdentity')
    $isTenantOwned     = $ownedAppIds.Contains([string]$sp.AppId)

    # --- Credentials ---------------------------------------------------------
    # Skipped entirely for managed identities. See the background note at the top: they have
    # no rotatable secret, and flagging them signals you do not know the platform.
    $creds = @()
    if (-not $isManagedIdentity) {
        $creds += Get-CredentialSummary -Credentials $sp.PasswordCredentials -Kind 'Password'
        $creds += Get-CredentialSummary -Credentials $sp.KeyCredentials      -Kind 'Certificate'
    }

    # --- Owners --------------------------------------------------------------
    # Only looked up for identities we actually own or manage. Microsoft first-party service
    # principals have no tenant owner BY DESIGN - looking them up wastes an API call per
    # identity and flagging them would be noise.
    $owners = @()
    if ($isTenantOwned -or $isManagedIdentity) {
        $owners = Get-OwnerSummary -ObjectId $sp.Id -Type 'ServicePrincipal'
    }

    # --- Permissions ---------------------------------------------------------
    $appRoles = @()
    if (-not $SkipPermissions) {
        $appRoles = Get-AppRoleSummary -ServicePrincipalId $sp.Id

        # Attach the human-readable permission name to each grant. -Force overwrites if the
        # property somehow already exists, which keeps re-runs safe.
        foreach ($r in $appRoles) {
            $r | Add-Member -NotePropertyName 'PermissionName' `
                 -NotePropertyValue (Resolve-AppRoleName -ResourceId $r.ResourceId -AppRoleId $r.AppRoleId) -Force
        }
    }

    # --- Sign-in activity ----------------------------------------------------
    # Joined by appId from the map we built in step 3.
    $signIn = $signInMap[[string]$sp.AppId]

    $inventory.Add([pscustomobject]@{
        ObjectClass          = 'ServicePrincipal'
        Id                   = $sp.Id
        AppId                = $sp.AppId
        DisplayName          = $sp.DisplayName
        ServicePrincipalType = $sp.ServicePrincipalType
        IsManagedIdentity    = $isManagedIdentity
        IsTenantOwned        = $isTenantOwned
        AccountEnabled       = $sp.AccountEnabled
        CreatedDateTime      = if ($sp.CreatedDateTime) { ([datetime]$sp.CreatedDateTime).ToString('o') } else { $null }
        Owners               = $owners
        OwnerCount           = $owners.Count
        Credentials          = $creds
        AppRoleAssignments   = $appRoles
        LastSignIn           = if ($signIn) { $signIn.lastSignInActivity.lastSignInDateTime } else { $null }

        # IMPORTANT: this flag distinguishes "we looked and found no record" from "we never
        # looked". Phase 3 needs that difference to avoid reporting an identity as unused
        # when we simply have no data about it.
        SignInRecordFound    = [bool]$signIn
    })
}
Write-Progress -Activity "Enumerating identities" -Completed


# -----------------------------------------------------------------------------
# App registrations are inventoried SEPARATELY from service principals.
# -----------------------------------------------------------------------------
# They are the definitions, and their credentials are the ones that actually get rotated.
# Treating them as the same object type as service principals is the conflation error
# described at the top of this script.
foreach ($app in $apps) {

    $creds  = @()
    $creds += Get-CredentialSummary -Credentials $app.PasswordCredentials -Kind 'Password'
    $creds += Get-CredentialSummary -Credentials $app.KeyCredentials      -Kind 'Certificate'

    $owners = Get-OwnerSummary -ObjectId $app.Id -Type 'Application'

    # --- Workload identity federation: a POSITIVE finding --------------------
    # Federated credentials mean the app authenticates using a token from an external issuer
    # (GitHub Actions, Kubernetes, another cloud) and has NO stored secret at all.
    #
    # This is the strongest possible remediation for credential findings - it does not rotate
    # the secret, it eliminates it. We detect it so the report can say so.
    #
    # A tool that only ever reports problems reads as noise. One that recognises good practice
    # reads as judgement.
    $fedCreds = @()
    try {
        $fed = Invoke-MgGraphRequest -Method GET `
               -Uri "https://graph.microsoft.com/v1.0/applications/$($app.Id)/federatedIdentityCredentials"

        foreach ($f in @($fed.value)) {
            $fedCreds += [pscustomobject]@{
                Name    = $f.name
                Issuer  = $f.issuer     # who is trusted to issue the token
                Subject = $f.subject    # WHICH identity from that issuer - over-broad subject
                                        # matching is the whole vulnerability class here
            }
        }
    }
    catch {
        Write-Verbose "No federated credentials readable for $($app.DisplayName)"
    }

    $inventory.Add([pscustomobject]@{
        ObjectClass                  = 'Application'
        Id                           = $app.Id
        AppId                        = $app.AppId
        DisplayName                  = $app.DisplayName
        ServicePrincipalType         = 'AppRegistration'
        IsManagedIdentity            = $false
        IsTenantOwned                = $true      # by definition - it is in our tenant
        AccountEnabled               = $null      # not applicable to app registrations
        CreatedDateTime              = if ($app.CreatedDateTime) { ([datetime]$app.CreatedDateTime).ToString('o') } else { $null }
        Owners                       = $owners
        OwnerCount                   = $owners.Count
        Credentials                  = $creds
        AppRoleAssignments           = @()
        FederatedIdentityCredentials = $fedCreds
        SignInAudience               = $app.SignInAudience
    })
}


# =============================================================================
# STEP 5 - Write the output and summarise
# =============================================================================
Write-Host "[5/5] Writing output..." -ForegroundColor Cyan

# The output records not just the data but the CONDITIONS it was gathered under: which
# tenant, when, which beta endpoints were involved. An assessment artifact that cannot say
# how it was produced is not much use to an auditor.
$payload = [pscustomobject]@{
    GeneratedUtc      = (Get-Date).ToUniversalTime().ToString('o')
    TenantId          = (Get-MgContext).TenantId
    ToolVersion       = '0.5-dev'
    BetaEndpointsUsed = @(if (-not $SkipSignInActivity) { 'reports/servicePrincipalSignInActivities' })
    Counts            = [pscustomobject]@{
        AppRegistrations  = $apps.Count
        ServicePrincipals = $sps.Count
        TenantOwned       = ($inventory | Where-Object IsTenantOwned).Count
        ManagedIdentities = ($inventory | Where-Object IsManagedIdentity).Count
        External          = ($inventory | Where-Object { -not $_.IsTenantOwned }).Count
    }
    Identities        = $inventory
}

# -Depth 12 matters. ConvertTo-Json defaults to depth 2 and will SILENTLY truncate nested
# objects - your credentials and owners would come out as the literal string
# "System.Object[]". This is one of the most common PowerShell data-loss bugs.
$payload | ConvertTo-Json -Depth 12 | Set-Content -Path $OutputPath -Encoding UTF8

$elapsed = [int]((Get-Date) - $script:StartTime).TotalSeconds

Write-Host ""
Write-Host "Inventory complete in ${elapsed}s" -ForegroundColor Green
Write-Host ("  App registrations : {0}" -f $payload.Counts.AppRegistrations)
Write-Host ("  Service principals: {0}" -f $payload.Counts.ServicePrincipals)
Write-Host ("  Tenant-owned      : {0}" -f $payload.Counts.TenantOwned)
Write-Host ("  Managed identities: {0}" -f $payload.Counts.ManagedIdentities)
Write-Host ("  External (MS/3rd) : {0}" -f $payload.Counts.External)
Write-Host ""

# A preview of the headline finding. Phase 3 does the real classification, but seeing this
# number at the end of Phase 1 is the moment the tool first justifies itself.
$noOwner = $inventory | Where-Object { $_.IsTenantOwned -and $_.OwnerCount -eq 0 }
if ($noOwner) {
    Write-Host "$($noOwner.Count) tenant-owned identities have NO OWNER." -ForegroundColor Yellow
    Write-Host "That is the headline finding. Phase 3 classifies and scores it." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Written to: $OutputPath"
Write-Host "This file contains REAL TENANT DATA - confirm .gitignore excludes it." -ForegroundColor Yellow
Write-Host "Next: .\03-New-OwnershipMap.ps1" -ForegroundColor Cyan
