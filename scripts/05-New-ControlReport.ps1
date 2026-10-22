<#
.SYNOPSIS
    Maps the Phase 3 findings to published control sets and produces an auditor-shaped
    report. This is v1.0 - the layer that makes the tool citable rather than merely useful.

.DESCRIPTION
    NIST, CSA and OWASP all published agentic control sets in February 2026. Every one of them
    tells you what SHOULD be true. Not one of them tells you whether it IS true in a specific
    tenant. This script is that missing layer, and it is the whole reason the tool is worth
    building.

    Reads  : output/nhi_findings.json       (from 03-New-OwnershipMap.ps1)
             reference/control-map.json      YOUR mapping - see the note below
    Writes : output/control_report.md

.PARAMETER ControlMapPath
    JSON mapping control IDs to finding codes. YOU write this after reading the source
    documents. A starter file is generated on first run if one does not exist.

.PARAMETER Anonymise
    Replace identity names with Identity-001, Identity-002 and so on. Use this for anything
    you publish - see the note at the bottom of this help.

.EXAMPLE
    .\05-New-ControlReport.ps1

.EXAMPLE
    .\05-New-ControlReport.ps1 -Anonymise
    Safe for publication - no real identity names in the output.

.NOTES
    THE CONTROL MAP IS YOURS TO WRITE, AND THAT IS DELIBERATE

    This script ships with PLACEHOLDER control IDs rather than real ones. That is not
    laziness - putting fabricated standard citations into an auditor-facing report is the
    fastest conceivable way to destroy the tool's credibility, and an auditor would catch it
    within minutes.

    Read the CSA AICM Agentic Control Supplement and the NIST NCCoE agent identity paper,
    then fill in reference/control-map.json yourself. The script warns loudly, in the console
    AND in the report, until you have.

    See reference/CONTROL-MAPPING.md for the table structure and for the list of controls
    that genuinely CANNOT be tested from directory data.
#>

[CmdletBinding()]
param(
    [string]$FindingsPath   = (Join-Path $PSScriptRoot '..\output\nhi_findings.json'),
    [string]$ControlMapPath = (Join-Path $PSScriptRoot '..\reference\control-map.json'),
    [string]$ReportPath     = (Join-Path $PSScriptRoot '..\output\control_report.md'),
    [switch]$Anonymise
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $FindingsPath)) {
    throw "Findings not found at $FindingsPath. Run 03-New-OwnershipMap.ps1 first."
}


# =============================================================================
# STEP 1 - The control map (generated as a starter if absent)
# =============================================================================
# The structure is the point here, not the content. Each entry answers four questions:
#   Which standard?  Which control?  Which of MY findings prove or disprove it?
#   And crucially - can it be fully tested at all, or only partially?
if (-not (Test-Path $ControlMapPath)) {

    Write-Warning "No control map found. Writing a starter to $ControlMapPath."
    Write-Warning "CONTROL IDs ARE PLACEHOLDERS. Replace them from the source documents"
    Write-Warning "before using this report anywhere real."

    $starter = @(
        # Testable = 'Full'    - the findings fully determine pass or fail
        # Testable = 'Partial' - you can test a NECESSARY but not SUFFICIENT condition.
        #                        Always pair this with a Limitation explaining the gap.
        @{ Source='CSA AICM Agentic'; ControlId='REPLACE-ME-01'
           Intent='Every agent and non-human identity has an accountable human owner'
           FindingCodes=@('NO_OWNER','ORPHANED_OWNER'); Testable='Full' }

        @{ Source='CSA AICM Agentic'; ControlId='REPLACE-ME-02'
           Intent='Credentials have a bounded, enforced lifetime'
           FindingCodes=@('CRED_NO_EXPIRY','CRED_LONG_LIVED','CRED_EXPIRED'); Testable='Full' }

        @{ Source='CSA AICM Agentic'; ControlId='REPLACE-ME-03'
           Intent='Permissions follow least privilege'
           FindingCodes=@('EXCESSIVE_SCOPE_ESCALATION','HIGH_IMPACT_PERMISSION'); Testable='Partial'
           # You can see WHAT permissions are held. You cannot see whether the business
           # actually needs them. Saying so is what keeps the report honest.
           Limitation='Can detect high-privilege grants. Cannot judge business necessity.' }

        @{ Source='CSA AICM Agentic'; ControlId='REPLACE-ME-04'
           Intent='Access is periodically re-certified by the owner'
           FindingCodes=@('ATTESTATION'); Testable='Full' }

        @{ Source='CSA AICM Agentic'; ControlId='REPLACE-ME-05'
           Intent='Unused identities are decommissioned'
           FindingCodes=@('DORMANT','DISABLED_WITH_CREDS'); Testable='Partial'
           Limitation='No sign-in record is not proof of disuse - may predate log retention.' }

        @{ Source='NIST NCCoE'; ControlId='REPLACE-ME-06'
           Intent='Authentication uses short-lived or federated credentials'
           FindingCodes=@('SECRET_OVER_CERT','FEDERATED_CRED'); Testable='Full' }
    )

    $dir = Split-Path $ControlMapPath -Parent
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $starter | ConvertTo-Json -Depth 6 | Set-Content $ControlMapPath -Encoding UTF8
}

$findingsDoc = Get-Content $FindingsPath   -Raw | ConvertFrom-Json
$controlMap  = Get-Content $ControlMapPath -Raw | ConvertFrom-Json


# =============================================================================
# STEP 2 - Invert the findings so they can be looked up by code
# =============================================================================
# Phase 3 produced data organised BY IDENTITY: "this app has these three problems."
# A control report needs the opposite: "which identities have this problem?"
#
# So we build a lookup keyed by finding code. One pass now saves scanning the whole findings
# set once per control later.
$byCode = @{}

foreach ($entry in $findingsDoc.Findings) {
    foreach ($f in $entry.Findings) {

        if (-not $byCode.ContainsKey($f.Code)) {
            $byCode[$f.Code] = [System.Collections.Generic.List[object]]::new()
        }

        $byCode[$f.Code].Add([pscustomobject]@{
            DisplayName = $entry.DisplayName
            AppId       = $entry.AppId
            Severity    = $f.Severity
            Detail      = $f.Detail
        })
    }
}


function Get-Label {
    <#  Returns either the real identity name or an anonymous placeholder.
        Centralised in one function so that -Anonymise cannot be partially applied -
        a report that anonymises most names but leaks three is worse than one that
        anonymises none, because it creates false confidence. #>
    param($Item, [int]$Index)
    if ($Anonymise) { return "Identity-{0:D3}" -f $Index }
    return $Item.DisplayName
}


# =============================================================================
# STEP 3 - Build the report
# =============================================================================
$md = [System.Collections.Generic.List[string]]::new()

$md.Add("# Agent & Non-Human Identity Posture Report")
$md.Add("")
$md.Add("**Generated:** $((Get-Date).ToString('yyyy-MM-dd HH:mm')) UTC  ")
$md.Add("**Identities with findings:** $(@($findingsDoc.Findings).Count)  ")
$md.Add("**Controls assessed:** $(@($controlMap).Count)")
$md.Add("")

# --- The placeholder guard ---------------------------------------------------
# If the control map still contains placeholder IDs, the report says so AT THE TOP, in the
# document itself - not just in the console where it is easily missed. A draft that looks
# finished is how fabricated citations end up in front of an auditor.
$placeholders = @($controlMap | Where-Object { $_.ControlId -like 'REPLACE-ME*' })

if ($placeholders.Count -gt 0) {
    $md.Add("> **DRAFT - control identifiers are placeholders.** $($placeholders.Count) control(s)")
    $md.Add("> still carry placeholder IDs. Replace them from the CSA AICM Agentic Control")
    $md.Add("> Supplement and the NIST NCCoE agent identity paper before this report is shown")
    $md.Add("> to anyone. Fabricated standard citations in an auditor-facing document are")
    $md.Add("> unrecoverable.")
    $md.Add("")
}

# --- Executive summary -------------------------------------------------------
# Count controls by outcome. A control with zero matching findings "passes" - with the
# important caveat that passing a partially-testable control means less than passing a fully
# testable one, which is why the two are counted separately.
$pass = 0; $fail = 0; $partial = 0

foreach ($c in $controlMap) {
    $hits = 0
    foreach ($code in $c.FindingCodes) {
        if ($byCode.ContainsKey($code)) { $hits += $byCode[$code].Count }
    }

    if ($hits -eq 0)                  { $pass++ }
    elseif ($c.Testable -eq 'Partial'){ $partial++ }
    else                              { $fail++ }
}

$md.Add("## Executive summary")
$md.Add("")
$md.Add("| | Count |")
$md.Add("|---|---:|")
$md.Add("| Controls with no findings | $pass |")
$md.Add("| Controls with findings | $fail |")
$md.Add("| Controls partially testable, with findings | $partial |")
$md.Add("")

# The three worst things, named, right at the top. An executive summary that makes a reader
# scroll to find the bad news is not a summary.
$critical = @()
foreach ($entry in $findingsDoc.Findings) {
    if ($entry.TopSeverity -eq 'Critical') { $critical += $entry }
}

if ($critical.Count -gt 0) {
    $md.Add("### Most serious findings")
    $md.Add("")
    $i = 0
    foreach ($c in ($critical | Select-Object -First 5)) {
        $i++
        $worst = ($c.Findings | Where-Object Severity -eq 'Critical' | Select-Object -First 1)
        $md.Add("$i. **$(Get-Label $c $i)** - $($worst.Detail)")
    }
    $md.Add("")
}

# --- Per-control detail ------------------------------------------------------
$md.Add("## Control results")
$md.Add("")

foreach ($c in $controlMap) {

    # Gather every identity that triggered any finding mapped to this control.
    $affected = [System.Collections.Generic.List[object]]::new()
    foreach ($code in $c.FindingCodes) {
        if ($byCode.ContainsKey($code)) {
            foreach ($x in $byCode[$code]) { $affected.Add($x) }
        }
    }

    $status = if ($affected.Count -eq 0) { 'PASS' } else { 'FINDINGS' }

    $md.Add("### $($c.ControlId) - $($c.Intent)")
    $md.Add("")
    $md.Add("**Source:** $($c.Source)  ")
    $md.Add("**Status:** $status  ")
    $md.Add("**Testability:** $($c.Testable)")

    # The limitation is printed with the result, not buried in an appendix. A reader needs to
    # know the boundary of the claim at the moment they read the claim.
    if ($c.Limitation) {
        $md.Add("")
        $md.Add("> **Limitation:** $($c.Limitation)")
    }
    $md.Add("")

    if ($affected.Count -gt 0) {
        $md.Add("**$($affected.Count) affected identit(ies):**")
        $md.Add("")
        $md.Add("| Identity | Severity | Detail |")
        $md.Add("|---|---|---|")
        $n = 0
        foreach ($a in ($affected | Sort-Object Severity)) {
            $n++
            $md.Add("| $(Get-Label $a $n) | $($a.Severity) | $($a.Detail) |")
        }
    }
    else { $md.Add("_No findings._") }

    $md.Add("")
}

# --- What this tool cannot tell you ------------------------------------------
# THIS SECTION IS A FEATURE, NOT AN APOLOGY.
#
# A tool that claims to assess controls it cannot actually measure is worse than one that is
# honestly scoped, and an auditor will find the overreach immediately. Publishing the
# boundary of your own tool is also the most interesting thing you will have to say to the
# standards community - it is precisely where the whole category currently stops.
$md.Add("## Not assessed")
$md.Add("")
$md.Add("These cannot be determined from directory data and require manual review. Listing")
$md.Add("them is deliberate: a tool that claims to assess controls it cannot measure is worse")
$md.Add("than one honestly scoped.")
$md.Add("")
$md.Add("| Not testable | Why |")
$md.Add("|---|---|")
$md.Add("| Whether a permission set is *necessary* | Business justification is not a directory attribute. Use the attestation cycle. |")
$md.Add("| Whether the agent was approved before creation | No approval record exists in Graph. This is a process control. |")
$md.Add("| Whether the identity handles regulated data | Data classification is not an identity property. |")
$md.Add("| Whether the assigned owner is the *right* owner | Graph records who the owner is, not whether that is appropriate. |")
$md.Add("| What the agent does when invoked | Behaviour is not an identity attribute. Runtime monitoring - out of scope for v1.0. |")
$md.Add("")

# --- Method ------------------------------------------------------------------
# Every caveat that affects how the findings should be read, collected in one place. An
# assessment artifact that cannot explain how it was produced is not much use to an auditor.
$md.Add("## Method and limitations")
$md.Add("")
$md.Add("- Read-only Microsoft Graph scopes: ``Application.Read.All``, ``Directory.Read.All``, ``AuditLog.Read.All``, ``RoleManagement.Read.Directory``")
$md.Add("- Sign-in activity uses a **beta** endpoint (``/beta/reports/servicePrincipalSignInActivities``) which may change without notice")
$md.Add("- **'No sign-in record' is not evidence of disuse.** A record may be absent because it predates the log retention window. Verify before decommissioning anything.")
$md.Add("- Managed identities are excluded from credential-rotation findings by design: Azure manages their credentials and there is nothing an administrator can rotate.")
$md.Add("- Microsoft first-party and third-party service principals are inventoried but not flagged for owner assignment - they have no tenant owner by design.")
$md.Add("")
$md.Add("---")
$md.Add("")
$md.Add("_Generated by 05-New-ControlReport.ps1._")


# =============================================================================
# STEP 4 - Write and summarise
# =============================================================================
$outDir = Split-Path $ReportPath -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

$md -join "`n" | Set-Content $ReportPath -Encoding UTF8

Write-Host ""
Write-Host "Control report written: $ReportPath" -ForegroundColor Green
Write-Host "  Controls assessed : $(@($controlMap).Count)"
Write-Host "  No findings       : $pass"
Write-Host "  With findings     : $fail"

if ($placeholders.Count -gt 0) {
    Write-Host ""
    Write-Host "!! $($placeholders.Count) control(s) still have PLACEHOLDER IDs." -ForegroundColor Red
    Write-Host "   Replace them from the source documents before showing this to anyone." -ForegroundColor Red
}

Write-Host ""
Write-Host "For anything you PUBLISH: use -Anonymise, and report aggregates only." -ForegroundColor Yellow
Write-Host "The client's report names their identities. Your article names nobody." -ForegroundColor Yellow
