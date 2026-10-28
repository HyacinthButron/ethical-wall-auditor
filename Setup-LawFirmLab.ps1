<#
.SYNOPSIS
    Creates a small fictional law firm setup in an existing Active Directory lab,
    used to test Test-EthicalWalls.ps1.

.DESCRIPTION
    Creates:
      - OU "LawFirm"
      - Groups: GRP-Matter-Alpha, GRP-Matter-Beta, GRP-Litigation
      - Users:  lina.holm (Alpha team), oskar.strand (Beta team), nora.falk (Litigation team)
      - Nesting: GRP-Litigation is a member of GRP-Matter-Beta
      - Folders: C:\Shares\Matters\Alpha and C:\Shares\Matters\Beta, locked with NTFS
        so only SYSTEM, Administrators and the matter group have access

    The starting state is CLEAN: nobody has access to both matters.
    All names are fictional. Run on the domain controller as a Domain Admin.

.EXAMPLE
    .\Setup-LawFirmLab.ps1
#>
[CmdletBinding()]
param(
    [string]$MattersRoot = 'C:\Shares\Matters'
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$domain   = Get-ADDomain
$domainDN = $domain.DistinguishedName
$netbios  = $domain.NetBIOSName
$ouName   = 'LawFirm'
$ouDN     = "OU=$ouName,$domainDN"

$password = Read-Host -AsSecureString 'Password for the test users (12+ characters, upper case, number, symbol)'

# --- 1. OU -----------------------------------------------------------------
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$ouName'" -SearchBase $domainDN -SearchScope OneLevel)) {
    New-ADOrganizationalUnit -Name $ouName -Path $domainDN -ProtectedFromAccidentalDeletion $false
    Write-Host "Created OU $ouName" -ForegroundColor Green
}

# --- 2. Groups -------------------------------------------------------------
foreach ($g in 'GRP-Matter-Alpha', 'GRP-Matter-Beta', 'GRP-Litigation') {
    if (-not (Get-ADGroup -Filter "Name -eq '$g'")) {
        New-ADGroup -Name $g -SamAccountName $g -GroupScope Global -GroupCategory Security -Path $ouDN
        Write-Host "Created group $g" -ForegroundColor Green
    }
}

# --- 3. Users --------------------------------------------------------------
$users = @(
    @{ Sam = 'lina.holm';    First = 'Lina';  Last = 'Holm'   },
    @{ Sam = 'oskar.strand'; First = 'Oskar'; Last = 'Strand' },
    @{ Sam = 'nora.falk';    First = 'Nora';  Last = 'Falk'   }
)
foreach ($u in $users) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.Sam)'")) {
        New-ADUser -Name "$($u.First) $($u.Last)" -GivenName $u.First -Surname $u.Last `
            -SamAccountName $u.Sam -UserPrincipalName "$($u.Sam)@$($domain.DNSRoot)" `
            -AccountPassword $password -Enabled $true -Path $ouDN
        Write-Host "Created user $($u.Sam)" -ForegroundColor Green
    }
}

# --- 4. Memberships (clean starting state) ----------------------------------
Add-ADGroupMember -Identity 'GRP-Matter-Alpha' -Members 'lina.holm'
Add-ADGroupMember -Identity 'GRP-Matter-Beta'  -Members 'oskar.strand', 'GRP-Litigation'
Add-ADGroupMember -Identity 'GRP-Litigation'   -Members 'nora.falk'
Write-Host 'Group memberships set' -ForegroundColor Green

# --- 5. Folders with locked NTFS permissions --------------------------------
$folders = @{ 'Alpha' = 'GRP-Matter-Alpha'; 'Beta' = 'GRP-Matter-Beta' }
foreach ($name in $folders.Keys) {
    $path  = Join-Path $MattersRoot $name
    $group = "$netbios\$($folders[$name])"
    New-Item -ItemType Directory -Force -Path $path | Out-Null
    # Remove inherited permissions, then grant only SYSTEM, Administrators and the matter group
    icacls $path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "${group}:(OI)(CI)M" | Out-Null
    Write-Host "Locked $path for $group" -ForegroundColor Green
}

Write-Host "`nDone. Starting state is clean: run .\Test-EthicalWalls.ps1 -WallsCsv .\walls.csv" -ForegroundColor Cyan
