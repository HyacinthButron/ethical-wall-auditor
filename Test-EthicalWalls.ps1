<#
.SYNOPSIS
    Ethical Wall Auditor: checks that no user has access to both sides of a conflict.

.DESCRIPTION
    Law firms separate teams working for clients with conflicting interests
    ("ethical walls" / informationsbarriarer). In IT these walls are usually built
    with AD security groups and NTFS folder permissions.

    For every wall in the CSV file, this script:
      1. Reads the NTFS permissions of both folders
      2. Expands every group to individual users, including nested groups
      3. Flags anyone who can read BOTH sides, and shows HOW they got access
      4. Flags broad access (Everyone, Authenticated Users, Users, Domain Users)
      5. Writes a CSV and an HTML report

    Read-only: the script never changes permissions or group memberships.

.PARAMETER WallsCsv
    CSV with columns: WallName, SideA_Name, SideA_Path, SideB_Name, SideB_Path

.PARAMETER OutputFolder
    Where to save the reports (default: .\reports)

.PARAMETER IncludeAdmins
    Also count administrators. By default SYSTEM, Administrators, Domain Admins
    and Enterprise Admins are skipped, because IT admins are expected to have access.

.EXAMPLE
    .\Test-EthicalWalls.ps1 -WallsCsv .\walls.csv

.NOTES
    Requires the ActiveDirectory PowerShell module (installed on domain controllers,
    or via RSAT). Works in Windows PowerShell 5.1 and PowerShell 7.
    Limitations: Deny permissions and share-level permissions are not evaluated,
    so results show POTENTIAL access (the safe side for an audit).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$WallsCsv,
    [string]$OutputFolder = '.\reports',
    [switch]$IncludeAdmins
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

# Well-known SIDs
$AdminSids    = @('S-1-5-18', 'S-1-3-0', 'S-1-5-32-544')   # SYSTEM, CREATOR OWNER, Administrators
$AdminRidRegex = '-(512|519)$'                              # Domain Admins, Enterprise Admins
$BroadSids    = @{
    'S-1-1-0'      = 'Everyone'
    'S-1-5-11'     = 'Authenticated Users'
    'S-1-5-32-545' = 'BUILTIN\Users'
}
$BroadRidRegex = '-513$'                                    # Domain Users

# ---------------------------------------------------------------------------
# Does this access rule allow reading the folder's contents?
# ---------------------------------------------------------------------------
function Test-ReadAccess {
    param($Rule)
    if ($Rule.AccessControlType -ne 'Allow') { return $false }
    $rights      = ([int64]$Rule.FileSystemRights) -band [int64]4294967295
    $readData    = [int64]1           # ReadData / ListDirectory
    $genericRead = [int64]2147483648  # GENERIC_READ
    $genericAll  = [int64]268435456   # GENERIC_ALL
    return ((($rights -band $readData) -ne 0) -or
            (($rights -band $genericRead) -ne 0) -or
            (($rights -band $genericAll) -ne 0))
}

# ---------------------------------------------------------------------------
# Expand a security principal (user or group) to individual users.
# $Via records the path, e.g. "GRP-Matter-Beta > GRP-Litigation".
# ---------------------------------------------------------------------------
function Get-PrincipalUsers {
    param(
        [string]$Sid,
        [string]$Via,
        [hashtable]$Seen
    )
    if ($Seen.ContainsKey($Sid)) { return }   # protects against circular nesting
    $Seen[$Sid] = $true

    $obj = Get-ADObject -LDAPFilter "(objectSid=$Sid)" -Properties objectClass, sAMAccountName
    if (-not $obj) { return }

    if ($obj.objectClass -eq 'user') {
        $user = Get-ADUser -Identity $obj.DistinguishedName -Properties Enabled
        $how  = $Via
        if ($Via -eq $user.SamAccountName) { $how = 'direct permission' }
        [pscustomobject]@{
            User    = $user.SamAccountName
            Name    = $user.Name
            Enabled = $user.Enabled
            Via     = $how
        }
    }
    elseif ($obj.objectClass -eq 'group') {
        foreach ($member in Get-ADGroupMember -Identity $obj.DistinguishedName) {
            if ($member.objectClass -eq 'group') {
                Get-PrincipalUsers -Sid $member.SID.Value -Via "$Via > $($member.SamAccountName)" -Seen $Seen
            }
            elseif ($member.objectClass -eq 'user') {
                Get-PrincipalUsers -Sid $member.SID.Value -Via $Via -Seen $Seen
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Who can read this folder?
# ---------------------------------------------------------------------------
function Get-FolderAccess {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Folder not found: $Path"
    }
    $users = @()
    $broad = @()

    foreach ($rule in (Get-Acl -LiteralPath $Path).Access) {
        if (-not (Test-ReadAccess $rule)) { continue }
        try {
            $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        } catch {
            Write-Warning "Could not resolve '$($rule.IdentityReference)' on $Path (deleted account?)"
            continue
        }

        if (-not $IncludeAdmins -and (($AdminSids -contains $sid) -or ($sid -match $AdminRidRegex))) { continue }

        if ($BroadSids.ContainsKey($sid) -or ($sid -match $BroadRidRegex)) {
            $broad += $rule.IdentityReference.Value
            continue
        }

        $name = $rule.IdentityReference.Value.Split('\')[-1]
        $users += @(Get-PrincipalUsers -Sid $sid -Via $name -Seen @{})
    }

    [pscustomobject]@{
        Users = $users
        Broad = @($broad | Select-Object -Unique)
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$walls = Import-Csv -LiteralPath $WallsCsv
New-Item -ItemType Directory -Force -Path $OutputFolder | Out-Null

$findings = @()
$summary  = @()

foreach ($wall in $walls) {
    Write-Host "`nChecking wall: $($wall.WallName)" -ForegroundColor Cyan
    $sideA = Get-FolderAccess -Path $wall.SideA_Path
    $sideB = Get-FolderAccess -Path $wall.SideB_Path
    $wallFindings = @()

    # 1. Broad access on either side breaks the wall for everyone
    foreach ($pair in @(@($wall.SideA_Name, $sideA), @($wall.SideB_Name, $sideB))) {
        foreach ($group in $pair[1].Broad) {
            $wallFindings += [pscustomobject]@{
                Wall     = $wall.WallName
                Severity = 'CRITICAL'
                User     = 'all users'
                Name     = $group
                Enabled  = ''
                AccessA  = $(if ($pair[0] -eq $wall.SideA_Name) { "$group has read access" } else { '' })
                AccessB  = $(if ($pair[0] -eq $wall.SideB_Name) { "$group has read access" } else { '' })
                Fix      = "Remove $group from $($pair[0]) and grant access only to the matter group"
            }
        }
    }

    # 2. Individual users with access to both sides
    $mapA = @{}
    foreach ($u in $sideA.Users) {
        if (-not $mapA.ContainsKey($u.User)) { $mapA[$u.User] = @() }
        $mapA[$u.User] += $u
    }
    foreach ($u in ($sideB.Users | Group-Object User)) {
        if ($mapA.ContainsKey($u.Name)) {
            $first = $u.Group[0]
            $severity = 'HIGH'
            if (-not $first.Enabled) { $severity = 'MEDIUM' }   # disabled account: stale access
            $wallFindings += [pscustomobject]@{
                Wall     = $wall.WallName
                Severity = $severity
                User     = $first.User
                Name     = $first.Name
                Enabled  = $first.Enabled
                AccessA  = (($mapA[$u.Name] | ForEach-Object { $_.Via } | Select-Object -Unique) -join '; ')
                AccessB  = (($u.Group        | ForEach-Object { $_.Via } | Select-Object -Unique) -join '; ')
                Fix      = 'Remove the user (or the nested group) from one side'
            }
        }
    }

    if ($wallFindings.Count -eq 0) {
        Write-Host "  PASS  Nobody has access to both $($wall.SideA_Name) and $($wall.SideB_Name)" -ForegroundColor Green
        $status = 'PASS'
    } else {
        foreach ($f in $wallFindings) {
            $color = 'Yellow'
            if ($f.Severity -eq 'CRITICAL' -or $f.Severity -eq 'HIGH') { $color = 'Red' }
            Write-Host "  $($f.Severity)  $($f.Name) ($($f.User))" -ForegroundColor $color
            if ($f.AccessA) { Write-Host "         $($wall.SideA_Name): $($f.AccessA)" }
            if ($f.AccessB) { Write-Host "         $($wall.SideB_Name): $($f.AccessB)" }
        }
        $status = 'FAIL'
    }

    $summary += [pscustomobject]@{
        Wall          = $wall.WallName
        Status        = $status
        UsersSideA    = @($sideA.Users | Select-Object -ExpandProperty User -Unique).Count
        UsersSideB    = @($sideB.Users | Select-Object -ExpandProperty User -Unique).Count
        Findings      = $wallFindings.Count
    }
    $findings += $wallFindings
}

# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
$stamp    = Get-Date -Format 'yyyy-MM-dd_HHmm'
$csvPath  = Join-Path $OutputFolder "EthicalWalls_$stamp.csv"
$htmlPath = Join-Path $OutputFolder "EthicalWalls_$stamp.html"

$findings | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

function Format-Html([string]$text) { [System.Net.WebUtility]::HtmlEncode($text) }

$rowsSummary = ($summary | ForEach-Object {
    $cls = 'pass'; if ($_.Status -eq 'FAIL') { $cls = 'fail' }
    "<tr><td>$(Format-Html $_.Wall)</td><td class='$cls'>$($_.Status)</td><td>$($_.UsersSideA)</td><td>$($_.UsersSideB)</td><td>$($_.Findings)</td></tr>"
}) -join "`n"

$rowsFindings = ($findings | ForEach-Object {
    "<tr><td>$(Format-Html $_.Wall)</td><td class='sev-$($_.Severity.ToLower())'>$($_.Severity)</td><td>$(Format-Html $_.Name)<br><small>$(Format-Html $_.User)</small></td><td>$(Format-Html $_.AccessA)</td><td>$(Format-Html $_.AccessB)</td><td>$(Format-Html $_.Fix)</td></tr>"
}) -join "`n"
if (-not $rowsFindings) { $rowsFindings = "<tr><td colspan='6' class='pass'>No findings. All ethical walls are intact.</td></tr>" }

$html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Ethical Wall Audit $stamp</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:40px;color:#1a1c1a;background:#f9fbf7}
h1{font-weight:400}table{border-collapse:collapse;width:100%;margin-bottom:32px;background:#fff}
th,td{border:1px solid #cfd8d1;padding:8px 10px;text-align:left;vertical-align:top}
th{background:#e8f1eb}.pass{color:#1e6b3c;font-weight:700}.fail{color:#b42318;font-weight:700}
.sev-critical,.sev-high{color:#b42318;font-weight:700}.sev-medium{color:#9a6700;font-weight:700}
small{color:#555}
</style></head><body>
<h1>Ethical Wall Audit</h1>
<p>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm') on $env:COMPUTERNAME. Read-only check of NTFS permissions and AD group membership (nested groups included).</p>
<h2>Summary</h2>
<table><tr><th>Wall</th><th>Status</th><th>Users side A</th><th>Users side B</th><th>Findings</th></tr>
$rowsSummary
</table>
<h2>Findings</h2>
<table><tr><th>Wall</th><th>Severity</th><th>Who</th><th>Access to side A</th><th>Access to side B</th><th>Suggested fix</th></tr>
$rowsFindings
</table>
<p><small>Admins (SYSTEM, Administrators, Domain Admins, Enterprise Admins) are excluded unless -IncludeAdmins is used. Deny entries and share permissions are not evaluated.</small></p>
</body></html>
"@
Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8

Write-Host "`nReports saved:" -ForegroundColor Cyan
Write-Host "  $csvPath"
Write-Host "  $htmlPath"

if ($findings.Count -gt 0) { exit 1 } else { exit 0 }
