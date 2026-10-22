<#
.SYNOPSIS
    Turns the raw inventory into classified findings: who owns each identity, what is wrong
    with it, and how serious that is.

.DESCRIPTION
    This is the PowerShell port of ownership_mapping.py from the multi-cloud repo, scoped to
    Entra and extended with the findings that script does not produce - orphaned owners,
    excessive scope, dormancy, and credential-type recommendations.

    Reads  : output/nhi_inventory.json   (produced by 01-Get-NHIInventory.ps1)
    Writes : output/nhi_ownership.csv    one row per identity, for humans and spreadsheets
             output/nhi_findings.json    structured findings, consumed by Phases 4 and 5

    Makes NO calls to the tenant. This is pure transformation of a file you already have,
    which means it is safe to run repeatedly while you tune the rules - and you will tune
    them, several times.

.PARAMETER DormancyDays
    How many days without a sign-in before an identity counts as dormant. Default 90.

.PARAMETER LongLivedSecretDays
    Secret lifetime beyond which it is flagged as excessively long. Default 180.

.PARAMETER TerraformStatePath
    OPTIONAL. Path to a Terraform state file, or a directory containing terraform.tfstate.

    Supply it and RULE 7 runs, classifying every tenant-owned app registration as declared
    in code or clicked into existence. OMIT IT AND RULE 7 IS SKIPPED ENTIRELY - an empty
    managed set would otherwise flag every identity in the tenant, which is exactly how an
    NHI report gets closed and never reopened.

    This is a BACKLOG feature, not part of v0.5 or v1.0. Read BACKLOG.md Item 1 first.

.EXAMPLE
    .\03-New-OwnershipMap.ps1

.EXAMPLE
    .\03-New-OwnershipMap.ps1 -DormancyDays 60 -LongLivedSecretDays 90
    Stricter thresholds - useful for showing a client the effect of tightening policy.

.EXAMPLE
    .\03-New-OwnershipMap.ps1 -TerraformStatePath ..\terraform\terraform.tfstate
    Adds IaC provenance. Produces the coverage figure: what percentage of PRIVILEGED
    non-human identities are declared in code rather than clicked into existence.

.NOTES
    THE SEVERITY MODEL
      Critical  Privilege escalation is possible, or the owner is gone
      High      Nobody can attest to it, or a credential has already failed
      Medium    A hygiene problem that will become High if ignored
      Low       A better practice is available
      Info      A POSITIVE finding - report good practice, not only problems

    RULE 7 (IaC provenance) IS OPT-IN and does nothing unless -TerraformStatePath is given.
    Its finding codes are IAC_MANAGED (Info), UNMANAGED_IDENTITY (Low) and
    UNMANAGED_PRIVILEGED (High). The severity split is deliberate and is explained in full
    at the rule itself - do not raise UNMANAGED_IDENTITY without reading that note.

    Every rule below is MECHANICALLY CHECKABLE. There are no judgement calls anywhere in this
    script. That is deliberate: a finding you can point at a specific field for is defensible
    to an auditor, and one based on your opinion is not.
#>

[CmdletBinding()]
param(
    [string]$InventoryPath = (Join-Path $PSScriptRoot '..\output\nhi_inventory.json'),
    [string]$CsvPath       = (Join-Path $PSScriptRoot '..\output\nhi_ownership.csv'),
    [string]$FindingsPath  = (Join-Path $PSScriptRoot '..\output\nhi_findings.json'),
    [int]$DormancyDays = 90,
    [int]$LongLivedSecretDays = 180,

    # OPTIONAL - path to a Terraform state file (or a directory containing one).
    #
    # Supply this and RULE 7 runs: every tenant-owned app registration gets classified as
    # either declared-in-code or clicked-into-existence. Leave it empty and RULE 7 is SKIPPED
    # ENTIRELY - see the long note above RULE 7 for why that is the only safe default.
    #
    # Backlog item. See BACKLOG.md Item 1 before using this in anger.
    [string]$TerraformStatePath = ''
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $InventoryPath)) {
    throw "Inventory not found at $InventoryPath. Run 01-Get-NHIInventory.ps1 first."
}

$data = Get-Content $InventoryPath -Raw | ConvertFrom-Json
$now  = (Get-Date).ToUniversalTime()


# #############################################################################
#  THE PERMISSION RISK SETS
# #############################################################################
#  This is where the tool stops being a list and starts being an assessment.
# #############################################################################

# -----------------------------------------------------------------------------
# PRIVILEGE ESCALATION SET
# -----------------------------------------------------------------------------
# Any service principal holding one of these can, directly or in a single further step,
# grant itself Global Administrator. Walk through why each one qualifies:
#
#   RoleManagement.ReadWrite.Directory
#       Can assign directory roles - including Global Administrator, to itself. The most
#       direct path there is.
#
#   AppRoleAssignment.ReadWrite.All
#       Can grant application permissions - so it can grant itself any OTHER permission,
#       including the one above. One step removed from the same outcome.
#
#   Application.ReadWrite.All
#       Can add credentials to ANY app registration, including highly privileged ones. Add a
#       secret to a privileged app, authenticate as it, inherit its permissions.
#
#   Directory.ReadWrite.All
#       Broad directory write. Less surgical than the others but still extremely powerful.
#
# A service principal holding one of these WITH NO OWNER is the single most alarming finding
# this tool can produce - and most tenants have at least one.
$EscalationPermissions = @(
    'RoleManagement.ReadWrite.Directory'
    'AppRoleAssignment.ReadWrite.All'
    'Application.ReadWrite.All'
    'Directory.ReadWrite.All'
)

# -----------------------------------------------------------------------------
# HIGH IMPACT SET
# -----------------------------------------------------------------------------
# These do not lead to Global Admin, but they give broad access to data or to users. Serious,
# and worth an owner's explicit confirmation - but distinct from escalation, and keeping the
# two categories separate is what stops your report crying wolf.
$HighImpactPermissions = @(
    'User.ReadWrite.All'
    'Group.ReadWrite.All'
    'GroupMember.ReadWrite.All'
    'Mail.ReadWrite'
    'Mail.Send'                              # can send mail AS anyone - a phishing primitive
    'Files.ReadWrite.All'
    'Sites.FullControl.All'
    'DeviceManagementConfiguration.ReadWrite.All'
)


function New-Finding {
    <#  Tiny constructor so every finding has an identical shape.
        Code is machine-readable and is what Phase 5 maps to controls.
        Detail is human-readable and is what appears in the report. #>
    param([string]$Code, [string]$Severity, [string]$Detail)
    [pscustomobject]@{ Code = $Code; Severity = $Severity; Detail = $Detail }
}


# #############################################################################
#  INFRASTRUCTURE-AS-CODE PROVENANCE  (RULE 7 support)
# #############################################################################
#  Every other rule in this script describes a PROPERTY of an identity - its owner, its
#  credentials, its permissions. This one describes where it CAME FROM.
#
#  An identity declared in a Terraform module has four things by construction:
#      an owner         the repository, and the team that owns the repository
#      a justification  the commit message and the pull request that merged it
#      a history        git log, with reviewers
#      an intended state  the module - which is what makes drift detectable at all
#
#  An identity someone clicked into existence in the portal has none of those four, and
#  nothing in the directory records the difference. So the question this supports is one no
#  other NHI tool asks:
#
#      "Which of your non-human identities are declared in code, and which were clicked
#       into existence?"
#
#  WARNING - THIS CODE HAS NEVER BEEN RUN. Like the rest of the scripts in this folder it
#  was written without a tenant or a Terraform install to test against. Verify it against
#  the sanitised fixture from BACKLOG.md Item 1 Step 1 BEFORE trusting a single number it
#  produces. The failure mode to watch for is a parser that silently returns nothing.
# #############################################################################

function Get-IaCManagedIds {
    <#
        .SYNOPSIS
        Reads a Terraform state file and returns the identity object IDs it declares.

        .OUTPUTS
        [System.Collections.Generic.HashSet[string]] of lower-cased GUIDs. HashSet rather than
        an array for the same reason script 01 uses one: this gets tested once per identity,
        so an O(n) array scan becomes O(n-squared) across a few hundred service principals.

        .NOTES
        Terraform state is JSON, schema version 4, shaped roughly:

            { "version": 4,
              "resources": [
                { "mode": "managed",
                  "type": "azuread_application",
                  "instances": [ { "attributes": { "object_id": "...", "client_id": "..." } } ] } ] }

        Two traps, both of which silently corrupt the coverage figure rather than erroring:

        1. mode must be "managed". A "data" entry is a READ-ONLY LOOKUP of something
           Terraform does not own. Counting those inflates your coverage percentage - and
           that percentage is the one number from this whole feature anyone will ever quote
           back at you, so it is the worst possible place to be wrong.

        2. The azuread provider renamed 'application_id' to 'client_id' at v3.0. Both are
           handled below. Do not take my word for either name: run
               terraform providers schema -json
           which dumps the exact schema for the provider version YOU have pinned. Ask the
           binary rather than the documentation - it cannot be out of date.
    #>
    param([Parameter(Mandatory)][string]$Path)

    $set = [System.Collections.Generic.HashSet[string]]::new()

    # Accept either a state file or a directory containing the conventional filename.
    $file = $Path
    if (Test-Path -Path $Path -PathType Container) {
        $file = Join-Path $Path 'terraform.tfstate'
    }
    if (-not (Test-Path -Path $file -PathType Leaf)) {
        throw "Terraform state not found at '$file'. RULE 7 cannot run without it."
    }

    $state = Get-Content -Path $file -Raw | ConvertFrom-Json

    if (-not $state.resources) {
        Write-Warning "State file at '$file' declares no resources. RULE 7 will treat every identity as undeclared, which is almost certainly wrong - check you pointed at the right state."
    }

    # Only these resource types create a directory identity. Anything else in state is
    # infrastructure, not an identity, and is none of this script's business.
    $identityTypes = @(
        'azuread_application'
        'azuread_service_principal'
        'azurerm_user_assigned_identity'
    )

    foreach ($r in @($state.resources)) {

        if ($r.mode -ne 'managed')          { continue }   # trap 1 - see .NOTES
        if ($r.type -notin $identityTypes)  { continue }

        foreach ($inst in @($r.instances)) {
            $a = $inst.attributes
            if (-not $a) { continue }

            # Collect every identifier the object might be matched on later. Entra will hand
            # us an object ID in some places and an application (client) ID in others, and
            # which one appears depends on the object class - so index both and let RULE 7
            # test whichever it has.
            foreach ($key in 'object_id', 'client_id', 'application_id', 'principal_id') {
                $v = $a.$key
                if ($v -and $v -is [string]) { [void]$set.Add($v.ToLower()) }
            }
        }
    }

    return $set
}


# Load the managed set ONCE, before the loop, rather than re-reading the file per identity.
$iacEnabled    = -not [string]::IsNullOrWhiteSpace($TerraformStatePath)
$iacManagedIds = $null

if ($iacEnabled) {
    $iacManagedIds = Get-IaCManagedIds -Path $TerraformStatePath
    Write-Host "IaC provenance: $($iacManagedIds.Count) identifier(s) declared in Terraform state." -ForegroundColor Cyan
} else {
    Write-Verbose "No -TerraformStatePath supplied. RULE 7 (IaC provenance) skipped."
}


# =============================================================================
# MAIN LOOP - classify every identity
# =============================================================================
$rows     = [System.Collections.Generic.List[object]]::new()   # flat, for the CSV
$findings = [System.Collections.Generic.List[object]]::new()   # structured, for Phases 4 and 5

foreach ($id in $data.Identities) {

    # Findings accumulate here for this one identity.
    $f = [System.Collections.Generic.List[object]]::new()


    # -------------------------------------------------------------------------
    # EARLY EXIT - external identities are inventoried but never flagged
    # -------------------------------------------------------------------------
    # Microsoft first-party and third-party SaaS service principals have no tenant owner BY
    # DESIGN. Flagging them for "no owner" would generate 150 false findings and is precisely
    # the mistake that makes NHI tools get ignored.
    #
    # We still record them - you want the complete picture, and "how many third-party apps
    # have been consented to in this tenant" is itself an interesting number - but they get a
    # separate classification and no findings.
    if (-not $id.IsTenantOwned -and -not $id.IsManagedIdentity) {
        $rows.Add([pscustomobject]@{
            DisplayName    = $id.DisplayName
            ObjectClass    = $id.ObjectClass
            Type           = $id.ServicePrincipalType
            Classification = 'External (Microsoft / third-party)'
            Owner          = 'N/A - not tenant-owned'
            OwnerCount     = 0
            Enabled        = $id.AccountEnabled
            Created        = $id.CreatedDateTime
            LastSignIn     = $id.LastSignIn
            TopSeverity    = 'Info'
            FindingCount   = 0
            Findings       = ''
            AppId          = $id.AppId
        })
        continue    # nothing further to assess
    }


    # -------------------------------------------------------------------------
    # RULE 1 - Ownership. The headline finding.
    # -------------------------------------------------------------------------
    $ownerNames = @()
    $orphaned   = $false

    foreach ($o in @($id.Owners)) {
        # Prefer UPN (unique, actionable) over display name (ambiguous).
        $ownerNames += ($o.UserPrincipalName ? $o.UserPrincipalName : $o.DisplayName)

        # THE SUBTLE ONE: an owner object that EXISTS but whose account is DISABLED is worse
        # than having no owner at all. A governance dashboard shows the identity as owned and
        # therefore governed; in reality the owner left the company months ago and nobody will
        # ever respond to an attestation request. It looks fine and is not.
        if ($o.AccountEnabled -eq $false) { $orphaned = $true }
    }

    if ($id.OwnerCount -eq 0) {
        $f.Add((New-Finding 'NO_OWNER' 'High' 'No owner assigned. Nobody can attest to this identity.'))
    }
    elseif ($orphaned) {
        $f.Add((New-Finding 'ORPHANED_OWNER' 'Critical' 'Assigned owner account is disabled. Appears governed but is not.'))
    }


    # -------------------------------------------------------------------------
    # RULE 1b - SPONSOR. The accountability object owner is not.
    # -------------------------------------------------------------------------
    # Added 22 Oct 2026, after the Savill transcript confirmed the model:
    #
    #   "Every single agent ID MUST have a sponsor. So this is the person responsible. They
    #    have accountability for the agent. They decide is this agent is still needed or not.
    #    So you won't end up with these orphaned agents. Now OPTIONALLY I can add owners.
    #    That would be from a technology perspective."
    #
    # Three roles, and only one of them is accountability:
    #   SPONSOR   mandatory on agent identities. Decides whether the agent is still needed.
    #   OWNER     optional. Technical permissions ON the agent.
    #   MANAGER   optional.
    #
    # THE ASYMMETRY, which is the most valuable thing in this script:
    #
    #   An agent IDENTITY cannot exist without an accountable human.
    #   An agent on an APPLICATION SERVICE PRINCIPAL can.
    #
    # Microsoft closed the orphaned-agent hole for the new object class and left it open for
    # the old one - and the old one is what a great many tenants are still producing. The lab's
    # own jobs-alert-agent is in exactly that state: two owners, one of them a service
    # principal, and no sponsor because the concept does not apply to it.
    #
    # PROPERTY NAME NOT YET VERIFIED. Script 02 has to find it. Until it does, this rule is
    # inert in the same way RULE 7 is - it runs only when the inventory actually carries the
    # field, so it cannot fire wrongly on data that does not have it.
    if ($null -ne $id.PSObject.Properties['IsAgentIdentity'] -and $id.IsAgentIdentity) {

        # An agent identity with no sponsor should be IMPOSSIBLE - Microsoft makes it mandatory
        # at creation. So finding one does not mean "untidy", it means something bypassed the
        # control, which is why this is Critical rather than High.
        if (-not $id.SponsorId) {
            $f.Add((New-Finding 'NO_SPONSOR' 'Critical' 'Agent identity with no sponsor. Microsoft makes sponsorship mandatory at creation, so this should not be possible - something bypassed the control path.'))
        }
    }
    elseif ($id.IsAgentClassified) {
        # Agent-shaped, but NOT an agent identity - i.e. secured by an application service
        # principal. The sponsor concept does not apply, so there is no mandatory accountability
        # at all. This is the normal state for pre-platform agents, and that is the point.
        $f.Add((New-Finding 'SP_SECURED_AGENT' 'Medium' 'Agent secured by an application service principal rather than an agent identity. No sponsor requirement applies, so nothing guarantees an accountable human.'))
    }


    # -------------------------------------------------------------------------
    # RULE 2 - Credential hygiene
    # -------------------------------------------------------------------------
    # Managed identities are skipped entirely. Azure rotates their credentials; there is
    # literally nothing for an administrator to act on. Flagging them would be a false
    # positive that signals you do not know the platform.
    if (-not $id.IsManagedIdentity) {

        $hasPassword = $false
        $hasCert     = $false

        foreach ($c in @($id.Credentials)) {
            if ($c.Kind -eq 'Password')    { $hasPassword = $true }
            if ($c.Kind -eq 'Certificate') { $hasCert = $true }

            # Order matters here - these are mutually exclusive states, checked worst first.
            if ($c.NoExpiry) {
                # A credential with no end date never expires and will never be rotated by
                # any process that keys off expiry. Genuinely dangerous.
                $f.Add((New-Finding 'CRED_NO_EXPIRY' 'High' "$($c.Kind) '$($c.DisplayName)' has no expiry date."))
            }
            elseif ($c.Expired -eq $true) {
                # Already expired but still configured. Either the identity is broken and
                # nobody noticed, or something is still using it - both are worth knowing.
                $f.Add((New-Finding 'CRED_EXPIRED' 'High' "$($c.Kind) '$($c.DisplayName)' expired $([math]::Abs($c.DaysLeft)) days ago but remains configured."))
            }
            elseif ($null -ne $c.DaysLeft -and $c.DaysLeft -gt $LongLivedSecretDays) {
                # Valid, but for far too long. The longer a secret lives, the longer a
                # compromise of it stays useful to an attacker.
                $f.Add((New-Finding 'CRED_LONG_LIVED' 'Medium' "$($c.Kind) valid for a further $($c.DaysLeft) days - exceeds the $LongLivedSecretDays day policy."))
            }
            elseif ($null -ne $c.DaysLeft -and $c.DaysLeft -le 30 -and $c.DaysLeft -ge 0) {
                # Operational warning rather than a security finding - but useful, because an
                # unnoticed expiry means an outage.
                $f.Add((New-Finding 'CRED_EXPIRING' 'Low' "$($c.Kind) expires in $($c.DaysLeft) days."))
            }
        }

        # A recommendation rather than a defect: certificates and federated credentials are
        # both stronger than client secrets.
        if ($hasPassword -and -not $hasCert) {
            $f.Add((New-Finding 'SECRET_OVER_CERT' 'Low' 'Uses a client secret where a certificate or federated credential would be stronger.'))
        }
    }


    # NOTE on agent identities and credentials, added 22 Oct 2026.
    # Savill, 17:43 - "It is the BLUEPRINT that authenticates. These agent identities we're
    # going to end up creating DO NOT HAVE THEIR OWN CREDENTIALS."
    #
    # So RULE 2 finding nothing on an agent identity is CORRECT, not a gap. The credential
    # risk for an agent lives on its BLUEPRINT, and the blueprint is a different object this
    # script does not yet read. Microsoft's own framing of why that matters:
    #
    #   "A compromise of the blueprint's credentials affects ALL agent identities under it,
    #    which is why blueprint count is a security boundary decision."
    #
    # One blueprint can mint 250 agent identities. Assessing the children and ignoring the
    # parent inspects the symptom and skips the cause. Blueprint credential assessment is a
    # Phase 2 deliverable - see LAB-GUIDE 2.1.

    # -------------------------------------------------------------------------
    # RULE 3 - Workload identity federation: a POSITIVE finding
    # -------------------------------------------------------------------------
    # Report good practice, not only problems. A tool that produces nothing but complaints
    # reads as noise; one that recognises when something is done well reads as judgement -
    # and the person reading it is far more likely to trust the complaints.
    if ($id.FederatedIdentityCredentials -and @($id.FederatedIdentityCredentials).Count -gt 0) {
        $f.Add((New-Finding 'FEDERATED_CRED' 'Info' "Uses workload identity federation ($(@($id.FederatedIdentityCredentials).Count) credential(s)) - no stored secret. Good practice."))
    }


    # -------------------------------------------------------------------------
    # RULE 4 - Excessive scope. The most valuable rule in the script.
    # -------------------------------------------------------------------------
    foreach ($r in @($id.AppRoleAssignments)) {
        $perm = $r.PermissionName
        if (-not $perm) { continue }   # unresolved GUID - cannot classify what we cannot name

        if ($perm -in $EscalationPermissions) {
            $f.Add((New-Finding 'EXCESSIVE_SCOPE_ESCALATION' 'Critical' "Holds '$perm' on $($r.ResourceDisplayName) - privilege escalation to Global Administrator is possible."))
        }
        elseif ($perm -in $HighImpactPermissions) {
            $f.Add((New-Finding 'HIGH_IMPACT_PERMISSION' 'High' "Holds '$perm' on $($r.ResourceDisplayName)."))
        }
    }


    # -------------------------------------------------------------------------
    # RULE 5 - Dormancy, and the distinction that keeps you honest
    # -------------------------------------------------------------------------
    # READ THIS CAREFULLY, because it is the difference between a careful tool and one that
    # gets an administrator to delete something they needed.
    #
    # "No sign-in record found" does NOT mean "unused". It can mean:
    #   - the identity genuinely has not been used, OR
    #   - its last use predates the log retention window, OR
    #   - it authenticates through a flow that is not captured in that report
    #
    # So we report NO_SIGNIN_RECORD and DORMANT as two different findings with different
    # severities and different wording. Never write "unused" in output you cannot prove.
    $ageDays = $null
    if ($id.CreatedDateTime) {
        $ageDays = [int]($now - ([datetime]$id.CreatedDateTime).ToUniversalTime()).TotalDays
    }

    # Only assess dormancy for identities old enough for it to mean anything. A service
    # principal created last week has not had a chance to be used.
    if ($id.ObjectClass -eq 'ServicePrincipal' -and $null -ne $ageDays -and $ageDays -gt $DormancyDays) {

        if ($id.LastSignIn) {
            # We have a record, so we can measure properly.
            $idle = [int]($now - ([datetime]$id.LastSignIn).ToUniversalTime()).TotalDays
            if ($idle -gt $DormancyDays) {
                # AGENT BASELINES ARE NOT HUMAN BASELINES. Added 22 Oct 2026.
                # Savill, 31:44 - "If I saw a human working 24 hours a day, that's a bit odd...
                # If I see an AGENT working 24 hours a day, that's EXPECTED."
                # And 36:22 - a user reading 500 documents in 5 minutes is exfiltration; an
                # agent scanning a thousand in 3 minutes is retrieval augmented generation.
                #
                # An agent may be invoked twice a year BY DESIGN and be perfectly healthy.
                # Frequency tells you almost nothing about an agent, so the service-account
                # threshold is reported under a separate code with its reasoning attached,
                # rather than being quietly applied to a population it was never written for.
                if ($id.IsAgentClassified) {
                    $f.Add((New-Finding 'DORMANT_AGENT' 'Low' "No sign-in for $idle days. NOTE: agent invocation is event-driven and may be infrequent by design - this is weaker evidence of disuse than it would be for a service account. Confirm with the sponsor before acting."))
                }
                else {
                    $f.Add((New-Finding 'DORMANT' 'Medium' "No sign-in for $idle days."))
                }
            }
        }
        elseif ($id.SignInRecordFound -eq $false) {
            # We looked and found nothing. Say exactly that, and say what it does not prove.
            $f.Add((New-Finding 'NO_SIGNIN_RECORD' 'Low' "No sign-in record found. NOT proof of disuse - may predate the log retention window. Verify before acting."))
        }
    }


    # -------------------------------------------------------------------------
    # RULE 6 - Disabled, but still holding credentials
    # -------------------------------------------------------------------------
    # Low severity because a disabled account cannot authenticate - but it is untidy, and if
    # anyone ever re-enables it the credentials come straight back with it.
    if ($id.AccountEnabled -eq $false -and @($id.Credentials).Count -gt 0) {
        $f.Add((New-Finding 'DISABLED_WITH_CREDS' 'Low' 'Account disabled but credentials remain configured.'))
    }


    # -------------------------------------------------------------------------
    # RULE 7 - IaC provenance: declared in code, or clicked into existence?
    # -------------------------------------------------------------------------
    # WHY THIS IS GUARDED, AND WHY THE GUARD IS NOT OPTIONAL
    #
    # If no state file was supplied, the managed set is empty - and an empty set means EVERY
    # identity tests as undeclared. The report would then flag all of them, which is the
    # textbook way an NHI tool gets closed and never reopened. It is the same mistake the
    # Microsoft first-party early-exit above exists to prevent, so the rule REFUSES TO RUN
    # rather than guessing. "No data" and "nothing is managed" are different claims and this
    # script will only ever make the one it can support.
    #
    # SEVERITY DESIGN - read this before changing the numbers
    #
    #   IAC_MANAGED           Info    A positive, like FEDERATED_CRED. Found in state.
    #   UNMANAGED_IDENTITY    Low     On its own this is a COVERAGE METRIC, not a
    #                                 vulnerability. Most tenants are near 100% undeclared,
    #                                 and a High finding that fires on everything is noise.
    #   UNMANAGED_PRIVILEGED  High    Undeclared AND holding escalation or high-impact
    #                                 permissions. THIS is the one that means something.
    #
    # The composite is the entire point. Joined with NO_OWNER it reads: this identity can
    # escalate to Global Administrator, nobody is accountable for it, and it exists outside
    # any declared configuration. Three findings you already produce, plus one new one.
    #
    # SCOPE - deliberately narrow, for now
    #
    # Only application-type service principals are assessed. A SYSTEM-assigned managed
    # identity is created and destroyed with its parent Azure resource and cannot be declared
    # independently, so flagging one as undeclared is a false positive. USER-assigned managed
    # identities CAN be declared (azurerm_user_assigned_identity) and telling the two apart
    # needs the ARM resource ID from alternativeNames - a refinement for later, noted in
    # BACKLOG.md rather than guessed at here.
    if ($iacEnabled -and -not $id.IsManagedIdentity) {

        $declared = $false
        foreach ($candidate in $id.Id, $id.AppId) {
            if ($candidate -and $iacManagedIds.Contains(([string]$candidate).ToLower())) {
                $declared = $true
                break
            }
        }

        if ($declared) {
            $f.Add((New-Finding 'IAC_MANAGED' 'Info' 'Declared in Terraform state - has a repository owner, a commit justification and a reviewable change history. Good practice.'))
        }
        else {
            # Was anything serious already found on this identity? Reuse the codes rather
            # than re-deriving privilege, so the two rules can never disagree.
            $codes = $f | ForEach-Object { $_.Code }
            $isPrivileged = ($codes -contains 'EXCESSIVE_SCOPE_ESCALATION') -or
                            ($codes -contains 'HIGH_IMPACT_PERMISSION')

            if ($isPrivileged) {
                $f.Add((New-Finding 'UNMANAGED_PRIVILEGED' 'High' 'Holds privileged permissions and is NOT declared in infrastructure-as-code. No commit, no review, no intended state to detect drift against.'))
            }
            else {
                $f.Add((New-Finding 'UNMANAGED_IDENTITY' 'Low' 'Not declared in infrastructure-as-code. Created outside any reviewable configuration. Coverage gap rather than a vulnerability on its own.'))
            }
        }
    }


    # -------------------------------------------------------------------------
    # ROLL UP - what is the worst thing wrong with this identity?
    # -------------------------------------------------------------------------
    # A numeric rank lets us sort severities properly. Sorting the strings alphabetically
    # would put 'Critical' before 'High' by luck and 'Low' before 'Medium' wrongly.
    $order = @{ 'Critical' = 5; 'High' = 4; 'Medium' = 3; 'Low' = 2; 'Info' = 1 }

    # Info findings are positives, so they must not count toward the problem tally.
    $actionable = $f | Where-Object { $_.Severity -ne 'Info' }

    $top = 'None'
    if ($f.Count -gt 0) {
        $top = ($f | Sort-Object { $order[$_.Severity] } -Descending | Select-Object -First 1).Severity
    }

    # Flat row for the CSV - one line per identity, openable in Excel.
    $rows.Add([pscustomobject]@{
        DisplayName    = $id.DisplayName
        ObjectClass    = $id.ObjectClass
        Type           = $id.ServicePrincipalType
        Classification = if ($id.IsManagedIdentity) { 'Managed identity' } else { 'Tenant-owned' }
        Owner          = if ($ownerNames) { $ownerNames -join '; ' } else { 'UNASSIGNED' }
        OwnerCount     = $id.OwnerCount
        Enabled        = $id.AccountEnabled
        Created        = $id.CreatedDateTime
        LastSignIn     = $id.LastSignIn
        TopSeverity    = $top
        FindingCount   = $actionable.Count
        Findings       = (($f | ForEach-Object { $_.Code }) -join '; ')
        AppId          = $id.AppId
    })

    # Structured record for Phases 4 and 5 - keeps the full detail the CSV flattens away.
    if ($f.Count -gt 0) {
        $findings.Add([pscustomobject]@{
            DisplayName = $id.DisplayName
            AppId       = $id.AppId
            ObjectId    = $id.Id
            ObjectClass = $id.ObjectClass
            Owner       = if ($ownerNames) { $ownerNames -join '; ' } else { $null }
            TopSeverity = $top
            Findings    = $f
        })
    }
}


# =============================================================================
# WRITE THE OUTPUT
# =============================================================================
$outDir = Split-Path $CsvPath -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

# -NoTypeInformation drops the #TYPE header line that older PowerShell writes and that makes
# the file awkward to open in Excel.
$rows | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

# The findings file records the thresholds used, so a report can always be traced back to the
# parameters that produced it. Two runs with different thresholds are different assessments.
[pscustomobject]@{
    GeneratedUtc = $now.ToString('o')
    # IaCStateChecked records whether RULE 7 ran at all. A report that does not say so
    # cannot be read correctly later: 'no UNMANAGED findings' means something completely
    # different when the rule was skipped than when it ran and found none.
    Parameters   = @{
        DormancyDays        = $DormancyDays
        LongLivedSecretDays = $LongLivedSecretDays
        IaCStateChecked     = $iacEnabled
        IaCDeclaredCount    = if ($iacEnabled) { $iacManagedIds.Count } else { $null }
    }
    Findings     = $findings
} | ConvertTo-Json -Depth 10 | Set-Content -Path $FindingsPath -Encoding UTF8


# =============================================================================
# SUMMARISE
# =============================================================================
Write-Host ""
Write-Host "Ownership mapping complete." -ForegroundColor Green
Write-Host "  $($rows.Count) identities classified"
Write-Host ""

foreach ($sev in 'Critical','High','Medium','Low') {
    $c = ($rows | Where-Object TopSeverity -eq $sev).Count
    if ($c -gt 0) {
        $colour = switch ($sev) { 'Critical' {'Red'} 'High' {'Yellow'} default {'Gray'} }
        Write-Host ("  {0,-9} {1}" -f $sev, $c) -ForegroundColor $colour
    }
}

# -----------------------------------------------------------------------------
# THE MONEY FINDING
# -----------------------------------------------------------------------------
# An identity that can escalate to Global Administrator AND has nobody responsible for it.
# This combination is what makes the whole tool land in a conversation - it is concrete,
# serious, and almost always present.
$crit = $findings | Where-Object {
    $_.Findings.Code -contains 'EXCESSIVE_SCOPE_ESCALATION' -and $_.Findings.Code -contains 'NO_OWNER'
}

if ($crit) {
    Write-Host ""
    Write-Host "!! $($crit.Count) identit(ies) hold escalation permissions AND have no owner." -ForegroundColor Red
    Write-Host "   This is the finding that makes the whole tool land in a conversation." -ForegroundColor Red
    foreach ($c in $crit) { Write-Host "     - $($c.DisplayName)" -ForegroundColor Red }
}

# -----------------------------------------------------------------------------
# IaC COVERAGE - the number that actually travels
# -----------------------------------------------------------------------------
# The per-identity rows are not where RULE 7 lands. THIS is:
#
#     "11% of your privileged non-human identities are declared in code."
#
# One percentage, trends over time, and it survives being repeated in a board meeting -
# which is more than can be said for a 400-row CSV.
#
# Computed over the PRIVILEGED SUBSET ONLY. A coverage figure diluted by every low-risk
# service principal in the tenant means nothing, and an auditor will say so. The full-estate
# figure is printed underneath it for context, clearly labelled as the different number it is.
if ($iacEnabled) {

    $assessed   = $findings | Where-Object { $_.Findings.Code -contains 'IAC_MANAGED' -or
                                             $_.Findings.Code -contains 'UNMANAGED_IDENTITY' -or
                                             $_.Findings.Code -contains 'UNMANAGED_PRIVILEGED' }

    $privileged = $findings | Where-Object { $_.Findings.Code -contains 'EXCESSIVE_SCOPE_ESCALATION' -or
                                             $_.Findings.Code -contains 'HIGH_IMPACT_PERMISSION' }

    $privDeclared = @($privileged | Where-Object { $_.Findings.Code -contains 'IAC_MANAGED' }).Count
    $privTotal    = @($privileged).Count

    $allDeclared  = @($assessed | Where-Object { $_.Findings.Code -contains 'IAC_MANAGED' }).Count
    $allTotal     = @($assessed).Count

    Write-Host ""
    Write-Host "Infrastructure-as-code coverage" -ForegroundColor Cyan

    if ($privTotal -gt 0) {
        $pct = [math]::Round(($privDeclared / $privTotal) * 100, 1)
        Write-Host ("  {0}% of PRIVILEGED identities are declared in code ({1} of {2})" -f $pct, $privDeclared, $privTotal) -ForegroundColor Cyan
        Write-Host "  ^ this is the figure to quote. The one below is not the same claim." -ForegroundColor DarkGray
    } else {
        Write-Host "  No privileged identities found - no privileged coverage figure to report." -ForegroundColor DarkGray
    }

    if ($allTotal -gt 0) {
        $pctAll = [math]::Round(($allDeclared / $allTotal) * 100, 1)
        Write-Host ("  {0}% of all assessed tenant-owned identities ({1} of {2})" -f $pctAll, $allDeclared, $allTotal) -ForegroundColor DarkGray
    }
}


# -----------------------------------------------------------------------------
# THE SECOND MONEY FINDING - privileged, unowned AND undeclared
# -----------------------------------------------------------------------------
# One step worse than the block above. An identity that can take over the tenant, that nobody
# is accountable for, and that exists outside any reviewable configuration. There is no
# document anywhere in the organisation that explains why this exists.
if ($iacEnabled) {
    $worst = $findings | Where-Object {
        $_.Findings.Code -contains 'UNMANAGED_PRIVILEGED' -and $_.Findings.Code -contains 'NO_OWNER'
    }

    if ($worst) {
        Write-Host ""
        Write-Host "!! $(@($worst).Count) identit(ies) are privileged, unowned AND undeclared in code." -ForegroundColor Red
        Write-Host "   Nothing in this organisation records why these exist." -ForegroundColor Red
        foreach ($w in $worst) { Write-Host "     - $($w.DisplayName)" -ForegroundColor Red }
    }
}


Write-Host ""
Write-Host "Written: $CsvPath"
Write-Host "         $FindingsPath"
Write-Host "Both contain REAL TENANT DATA - confirm .gitignore excludes them." -ForegroundColor Yellow
Write-Host "Next: .\04-Invoke-AttestationCycle.ps1 -Simulate" -ForegroundColor Cyan
