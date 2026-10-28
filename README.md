# Ethical Wall Auditor

A read-only PowerShell tool that answers one question:

> **Does anyone have access to both sides of a conflict of interest right now?**

Law firms keep teams that work for clients with conflicting interests apart. These barriers are called
**ethical walls** (Swedish: *informationsbarriärer*). In IT, they're usually just security groups and folder
permissions, and they break quietly: someone is added to the wrong group, or gets access through a nested
group nobody remembers. This script finds those breaks and explains how the access happened.

**Read the full lab report: [LAB-REPORT.md](LAB-REPORT.md)**

## Results from my lab

I built a fictional law firm in my Active Directory home lab, broke the wall on purpose in two ways and
checked that the tool caught both.

| Test | What I changed | Result |
|---|---|---|
| Baseline | Nothing | ✅ PASS |
| Nested group | Added Nora to the Alpha team. She already reached Beta through `GRP-Litigation` | 🔴 HIGH, both access paths shown |
| Open folder | Gave `BUILTIN\Users` read access to the Beta folder | 🔴 CRITICAL |
| After fixing | Removed Nora from Alpha, removed the Users permission | ✅ PASS |

![Nested group conflict detected](screenshots/06-nested-group-conflict.png)

![HTML report](screenshots/07-conflict-html-report.png)

## What it does

For every wall in `walls.csv`, the script:

1. Reads the NTFS permissions on both folders
2. Expands every group to individual users, **including nested groups**
3. Flags anyone who can reach **both** sides, and shows **how**, e.g. `GRP-Matter-Beta > GRP-Litigation`
4. Flags **broad access** (Everyone, Authenticated Users, Users, Domain Users) as critical
5. Writes a CSV and an HTML report, and exits with code 1 if anything is found, so it can run as a scheduled task

It never changes anything. It only reads.

| Severity | Meaning |
|---|---|
| CRITICAL | A broad group can read one side, so the wall doesn't exist |
| HIGH | An enabled user can reach both sides |
| MEDIUM | A disabled user can reach both sides (stale access to clean up) |

## Quick start

Run on a domain controller, or on a machine with RSAT and read access to the folders, in PowerShell as admin:

```powershell
cd C:\Tools\EthicalWalls
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass   # this window only
Get-ChildItem | Unblock-File
.\Test-EthicalWalls.ps1 -WallsCsv .\walls.csv
```

`walls.csv` lists the folders that must never share users:

```csv
WallName,SideA_Name,SideA_Path,SideB_Name,SideB_Path
Alpha vs Beta,Matter Alpha,C:\Shares\Matters\Alpha,Matter Beta,C:\Shares\Matters\Beta
```

Options:

* `-OutputFolder .\reports`: where reports are saved
* `-IncludeAdmins`: also count SYSTEM, Administrators, Domain Admins and Enterprise Admins

### Try it in a lab

`Setup-LawFirmLab.ps1` creates the fictional law firm used in the report: an OU, three users, three groups
(one nested) and two locked matter folders. **Only run it in a lab domain.**

```powershell
.\Setup-LawFirmLab.ps1
```

## Files

| File | Purpose |
|---|---|
| `Test-EthicalWalls.ps1` | The auditor |
| `walls.csv` | The walls to check |
| `Setup-LawFirmLab.ps1` | Creates the fictional test setup in a lab domain |
| `LAB-REPORT.md` | Step-by-step lab report with screenshots |
| `screenshots/` | Evidence from the lab run |

## Limitations

* **Deny** entries and **share** permissions aren't evaluated, so results show *potential* access. For an audit,
  that's the safe side.
* Only the folders listed are checked, not individual files with their own permissions.
* Requires the `ActiveDirectory` PowerShell module.
* Tested in a home lab with fictional users, not in production.

## Skills shown

PowerShell · Active Directory (OUs, users, nested security groups) · NTFS permissions and `icacls` ·
access auditing · troubleshooting and verification · CSV/HTML reporting
