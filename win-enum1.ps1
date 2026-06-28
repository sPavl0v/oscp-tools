param(
    [string]$OutFile = ".\enum_report.txt",
    [switch]$Deep
)

# =========================
# Windows Low-Priv / Admin File-Cred Hunting
# Single-file output version
# Excludes services and scheduled tasks by design
# UTF-8 output for Windows/Linux readability
# =========================

$ErrorActionPreference = "SilentlyContinue"

# ---------- Setup ----------
$parent = Split-Path -Parent $OutFile
if ($parent -and -not (Test-Path $parent)) {
    New-Item -ItemType Directory -Path $parent | Out-Null
}

# Create/overwrite as clean UTF-8 without BOM
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutFile, "", $utf8NoBom)

$global:Findings = New-Object System.Collections.Generic.List[Object]

function Append-Utf8Text {
    param([string]$Text)

    if ($null -eq $Text) {
        $Text = ""
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::AppendAllText($OutFile, $Text, $utf8NoBom)
}

function Write-Section {
    param([string]$Title)
    $line = "`r`n========== $Title ==========`r`n"
    Write-Host $line -NoNewline
    Append-Utf8Text $line
}

function Write-Info {
    param([string]$Text)

    if ($null -eq $Text) {
        $Text = ""
    }

    Write-Host $Text
    Append-Utf8Text ($Text + "`r`n")
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Source,
        [string]$Path,
        [string]$Detail
    )

    $obj = [PSCustomObject]@{
        Category = $Category
        Severity = $Severity
        Source   = $Source
        Path     = $Path
        Detail   = $Detail
    }

    $global:Findings.Add($obj) | Out-Null
}

function Test-IsAdmin {
    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Score-ContentHit {
    param([string]$Line)

    $l = $Line.ToLower()

    if ($l -match 'defaultpassword|autoadminlogon|password\s*=|passwd\s*=|pwd\s*=|user id=.*password=|username=.*password=|net use .* /user:.*\s+\S+|convertto-securestring\s+".*"\s+-asplaintext') {
        return "High"
    }
    elseif ($l -match 'password|passwd|pwd|apikey|api_key|connectionstring|connstr|cmdkey|runas|net use|securestring|sqlcmd|invoke-sqlcmd|bindpw|binddn') {
        return "Medium"
    }
    else {
        return "Low"
    }
}

function Score-FileName {
    param([string]$Name)

    $n = $Name.ToLower()

    if ($n -match 'unattend|sysprep|groups\.xml|services\.xml|scheduledtasks\.xml|drives\.xml|cred|password|secret|token|backup|backups|\.bak$|\.old$|windows\.old|id_rsa|\.kdbx$|\.ppk$|\.pem$|\.key$') {
        return "High"
    }
    elseif ($n -match 'config|rdp|vpn|db|sql|reg|ini|xml|json|yaml|yml|conf|cfg|old') {
        return "Medium"
    }
    else {
        return "Low"
    }
}

function Add-FilePreviewFinding {
    param(
        [string]$Category,
        [string]$Path
    )

    $severity = Score-FileName -Name ([IO.Path]::GetFileName($Path))
    Add-Finding -Category $Category -Severity $severity -Source "Filename" -Path $Path -Detail "Suspicious filename/path"
}

function Get-MatchSnippet {
    param(
        [string]$Line,
        [string]$MatchedText,
        [int]$CharsAfter = 30
    )

    if ([string]::IsNullOrEmpty($Line) -or [string]::IsNullOrEmpty($MatchedText)) {
        return $Line
    }

    $idx = $Line.IndexOf($MatchedText, [System.StringComparison]::OrdinalIgnoreCase)
    if ($idx -lt 0) {
        return $null
    }

    $length = $MatchedText.Length + $CharsAfter
    if (($idx + $length) -gt $Line.Length) {
        $length = $Line.Length - $idx
    }

    $snippet = $Line.Substring($idx, $length)
    $snippet = $snippet -replace "`r", " "
    $snippet = $snippet -replace "`n", " "
    $snippet = $snippet -replace "`t", " "
    $snippet = $snippet.Trim()

    if ($snippet.Length -gt 120) {
        $snippet = $snippet.Substring(0,120)
    }

    return $snippet
}

# ---------- Exclusions ----------
$scriptExcludeNames = @("win-enum1.ps1", "desktop.ini")

$excludedExtensions = @(
    ".jrs", ".edb", ".chk", ".blf", ".regtrans-ms", ".etl", ".evtx", ".tmp", ".cache", ".dat",
    ".dll", ".rll", ".lnk", ".ocx", ".cpl", ".mui",
    ".db", ".db-wal", ".db-shm", ".db-journal", ".sqlite", ".sqlite3", ".sdb", ".mdb", ".accdb"
)

$excludedPathPrefixes = @(
    "C:\ProgramData\Microsoft\",
    "C:\ProgramData\Package Cache\",
    "C:\Windows\WinSxS\",
    "C:\Windows\Installer\",
    "C:\Windows\System32\DriverStore\",
    "C:\Windows\Servicing\",
    "C:\Windows\Microsoft.NET\",
    "C:\Windows\System32\Sysprep\ActionFiles\",
    "C:\Users\Default\AppData\Local\Microsoft\",
    "C:\Users\Default\AppData\Local\Packages\"
)

$excludedPathContains = @(
    "\Local Settings\",
    "\Application Data\Application Data\",
    "\Application Data\Local Settings\",
    "\Temporary Internet Files\",
    "\INetCache\",
    "\Content.IE5\",
    "\WindowsApps\",
    "Programs\Microsoft VS Code",
    "AppData\Roaming\Code",
    "\Packages\Microsoft",
    "Windows\System32",
    "Program Files (x86)\Microsoft",
    "Program Files (x86)\Windows",
    "\VMware",
    "\Modules\Microsoft",
    "\Application Data\Microsoft",
    "\All Users\Microsoft",
    "\Common Files\Microsoft",
    "\Program Files\Windows"
)

# Broad user-profile Microsoft/Windows-related noise to exclude
# Keep exceptions for known high-value paths below.
$excludedUserMicrosoftPathContains = @(
    "\AppData\Local\Microsoft\",
    "\AppData\Roaming\Microsoft\",
    "\AppData\Local\Application Data\Microsoft\",
    "\AppData\Roaming\Application Data\Microsoft\",
    "\AppData\Local\Windows\",
    "\AppData\Roaming\Windows\",
    "\AppData\Local\Application Data\Windows\",
    "\AppData\Roaming\Application Data\Windows\"
)

# Exceptions to the broad Microsoft/Windows exclusions above.
# These stay searchable.
$allowedUserMicrosoftPathContains = @(
    "\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\",
    "\AppData\Local\Microsoft\Remote Desktop Connection Manager\"
)

function Test-IsExcludedFileName {
    param([string]$Name)

    foreach ($n in $scriptExcludeNames) {
        if ($Name -ieq $n) {
            return $true
        }
    }
    return $false
}

function Test-IsExcludedExtension {
    param([string]$Extension)

    if ([string]::IsNullOrEmpty($Extension)) {
        return $false
    }

    $extLower = $Extension.ToLower()

    foreach ($ext in $excludedExtensions) {
        if ($extLower -ieq $ext) {
            return $true
        }
    }

    # Catch db-like variants not explicitly listed
    if ($extLower -like ".db*") {
        return $true
    }

    return $false
}

function Test-IsExcludedPath {
    param([string]$Path)

    foreach ($prefix in $excludedPathPrefixes) {
        if ($Path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

function Test-IsExcludedPathContains {
    param([string]$Path)

    foreach ($frag in $excludedPathContains) {
        if ($Path.IndexOf($frag, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

function Test-IsAllowedUserMicrosoftPath {
    param([string]$Path)

    foreach ($frag in $allowedUserMicrosoftPathContains) {
        if ($Path.IndexOf($frag, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

function Test-IsExcludedUserMicrosoftPath {
    param([string]$Path)

    if (Test-IsAllowedUserMicrosoftPath $Path) {
        return $false
    }

    foreach ($frag in $excludedUserMicrosoftPathContains) {
        if ($Path.IndexOf($frag, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    return $false
}

function Test-IsReparsePoint {
    param($Item)

    try {
        return [bool]($Item.Attributes -band [IO.FileAttributes]::ReparsePoint)
    } catch {
        return $false
    }
}

$IsAdmin = Test-IsAdmin

# ---------- Header ----------
Write-Section "Run Info"
Write-Info "Date: $(Get-Date)"
Write-Info "Output file: $OutFile"
Write-Info "Deep mode: $Deep"
Write-Info "Is admin: $IsAdmin"

# ---------- Baseline ----------
Write-Section "Host / User Baseline"

$baseline = @()
$baseline += "Date: $(Get-Date)"
$baseline += "ComputerName: $env:COMPUTERNAME"
$baseline += "UserName: $env:USERNAME"
$baseline += "UserDomain: $env:USERDOMAIN"
$baseline += "UserProfile: $env:USERPROFILE"
$baseline += "PSVersion: $($PSVersionTable.PSVersion)"
$baseline += ""
$baseline += "whoami /all:"
$baseline += (whoami /all)

$baselineText = $baseline -join "`r`n"
Write-Info $baselineText

# ---------- Env Vars ----------
Write-Section "Environment Variables"
$envDump = (Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize | Out-String)
Write-Info $envDump

# ---------- cmdkey ----------
Write-Section "Credential Manager (cmdkey /list)"
$cmdkeyOut = cmdkey /list 2>&1 | Out-String
Write-Info $cmdkeyOut

if ($cmdkeyOut -match 'Target:') {
    Add-Finding -Category "SavedCreds" -Severity "Medium" -Source "cmdkey" -Path "Credential Manager" -Detail "Saved credentials entries exist"
}

# ---------- Winlogon Auto Logon ----------
Write-Section "Winlogon Autologon Check"
$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$winlogon = Get-ItemProperty -Path $winlogonPath
$winlogonText = $winlogon | Format-List * | Out-String
Write-Info $winlogonText

if ($winlogon.DefaultPassword) {
    Add-Finding -Category "RegistryCreds" -Severity "High" -Source "Winlogon" -Path $winlogonPath -Detail "DefaultPassword present: $($winlogon.DefaultPassword)"
}
if ($winlogon.AutoAdminLogon -eq "1") {
    Add-Finding -Category "RegistryCreds" -Severity "High" -Source "Winlogon" -Path $winlogonPath -Detail "AutoAdminLogon enabled"
}
if ($winlogon.DefaultUserName) {
    Add-Finding -Category "RegistryCreds" -Severity "Medium" -Source "Winlogon" -Path $winlogonPath -Detail "DefaultUserName present: $($winlogon.DefaultUserName)"
}

# ---------- PowerShell History OLD ----------
# Write-Section "PowerShell History"
# $psHist = Join-Path $env:APPDATA "Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
# if (Test-Path $psHist) {
#     $histText = Get-Content $psHist -ErrorAction SilentlyContinue | Out-String
#     Write-Info $histText

#     $histPatterns = @(
#         'password', 'passwd', 'pwd', 'net use', 'runas', 'cmdkey',
#         'ConvertTo-SecureString', 'SecureString', 'sqlcmd', 'Invoke-Sqlcmd',
#         'Enter-PSSession', 'Invoke-Command'
#     )

#     foreach ($line in Get-Content $psHist -ErrorAction SilentlyContinue) {
#         foreach ($p in $histPatterns) {
#             if ($line -match [regex]::Escape($p)) {
#                 $sev = Score-ContentHit -Line $line
#                 Add-Finding -Category "ShellHistory" -Severity $sev -Source "PSReadLine" -Path $psHist -Detail $line.Trim()
#                 break
#             }
#         }
#     }
# } else {
#     Write-Info "PowerShell history file not found."
# }


# ---------- Global Multi-User Enumeration ----------
Write-Section "PowerShell History"

# Get all user folders, excluding common system folders
$userFolders = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue

foreach ($userDir in $userFolders) {
    $username = $userDir.Name
    Write-Section "Targeting User: ${username}"
    
    # --- 1. PSReadLine History for this specific user ---
    # Path: C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    $historyPath = Join-Path $userDir.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    
    if (Test-Path $historyPath) {
        Write-Info "FOUND HISTORY for ${username} at $historyPath"
        Write-Info "------------------ [${username}] HISTORY START ------------------"
        Get-Content $historyPath -ErrorAction SilentlyContinue | ForEach-Object { Write-Output $_ }
        Write-Info "------------------- [${username}] HISTORY END -------------------"
    } else {
        Write-Warning "No PSReadLine history accessible for ${username}."
    }

    # --- 2. Transcripts for this specific user ---
    # We look in Documents and common root folders within their profile
    $transcriptSearchPaths = @(
        $userDir.FullName, # Root of profile
        (Join-Path $userDir.FullName "Documents"),
        (Join-Path $userDir.FullName "Desktop")
    )

    foreach ($tPath in $transcriptSearchPaths) {
        if (Test-Path $tPath) {
            $transcripts = Get-ChildItem -Path $tPath -Filter "*transcript*.txt" -Recurse -Depth 2 -ErrorAction SilentlyContinue
            
            foreach ($file in $transcripts) {
                # Verify it's a real transcript
                $firstLine = Get-Content $file.FullName -TotalCount 1 -ErrorAction SilentlyContinue
                if ($firstLine -match "Windows PowerShell Transcript Start") {
                    Write-Info "FOUND TRANSCRIPT for ${username}: $($file.FullName)"
                    Write-Info "------------------ [${username}] TRANSCRIPT START ------------------"
                    Get-Content $file.FullName | ForEach-Object { Write-Output $_ }
                    Write-Info "------------------- [${username}] TRANSCRIPT END -------------------"
                }
            }
        }
    }
}

# --- 3. Global Check for Enforced Transcripts (GPO) ---
Write-Section "System-Wide (GPO) Transcripts"
$regPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcripting"
if (Test-Path $regPath) {
    $gpoPath = Get-ItemProperty -Path $regPath -Name "OutputDirectory" -ErrorAction SilentlyContinue
    if ($gpoPath.OutputDirectory) {
        Write-Info "GPO Enforced Transcript Path Found: $($gpoPath.OutputDirectory)"
        Get-ChildItem -Path $gpoPath.OutputDirectory -Filter "*.txt" -Recurse | ForEach-Object {
            Write-Info "Dumping GPO Transcript: $($_.FullName)"
            Get-Content $_.FullName | ForEach-Object { Write-Output $_ }
        }
    }
}



# ---------- App / Tool Specific Paths ----------
Write-Section "App-Specific High-Yield Checks"

$appChecks = @(
    @{ Name="PuTTY Sessions"; Type="Registry"; Path="HKCU:\Software\SimonTatham\PuTTY\Sessions" },
    @{ Name="WinSCP Sessions"; Type="Registry"; Path="HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions" },
    @{ Name="WinSCP INI"; Type="File"; Path=(Join-Path $env:APPDATA "WinSCP.ini") },
    @{ Name="FileZilla SiteManager"; Type="File"; Path=(Join-Path $env:APPDATA "FileZilla\sitemanager.xml") },
    @{ Name="FileZilla RecentServers"; Type="File"; Path=(Join-Path $env:APPDATA "FileZilla\recentservers.xml") },
    @{ Name="Default RDP"; Type="File"; Path=(Join-Path $env:USERPROFILE "Documents\Default.rdp") },
    @{ Name="RDCMan"; Type="File"; Path=(Join-Path $env:LOCALAPPDATA "Microsoft\Remote Desktop Connection Manager\RDCMan.settings") },
    @{ Name="mRemoteNG"; Type="File"; Path=(Join-Path $env:APPDATA "mRemoteNG\confCons.xml") },
    @{ Name="AWS Credentials"; Type="File"; Path=(Join-Path $env:USERPROFILE ".aws\credentials") },
    @{ Name="AWS Config"; Type="File"; Path=(Join-Path $env:USERPROFILE ".aws\config") },
    @{ Name="Azure Profile"; Type="Dir"; Path=(Join-Path $env:USERPROFILE ".azure") },
    @{ Name="Kube Config"; Type="File"; Path=(Join-Path $env:USERPROFILE ".kube\config") },
    @{ Name="Git Credentials"; Type="File"; Path=(Join-Path $env:USERPROFILE ".git-credentials") },
    @{ Name="SSH Directory"; Type="Dir"; Path=(Join-Path $env:USERPROFILE ".ssh") },
    @{ Name="npmrc"; Type="File"; Path=(Join-Path $env:USERPROFILE ".npmrc") },
    @{ Name="pypirc"; Type="File"; Path=(Join-Path $env:USERPROFILE ".pypirc") }
)

foreach ($item in $appChecks) {
    switch ($item.Type) {
        "Registry" {
            if (Test-Path $item.Path) {
                $regOut = (Get-ItemProperty -Path $item.Path -ErrorAction SilentlyContinue | Format-List * | Out-String)
                Write-Info "`r`n[$($item.Name)]`r`n$($item.Path)`r`n$regOut"
                Add-Finding -Category "AppArtifacts" -Severity "Medium" -Source $item.Name -Path $item.Path -Detail "Registry key exists"
            }
        }
        "File" {
            if (Test-Path $item.Path) {
                if (-not (Test-IsExcludedExtension ([IO.Path]::GetExtension($item.Path)))) {
                    Write-Info "`r`n[$($item.Name)]`r`n$($item.Path)"
                    try {
                        $content = Get-Content -LiteralPath $item.Path -ErrorAction SilentlyContinue | Select-Object -First 200 | Out-String
                        Write-Info $content
                    } catch {}
                    Add-Finding -Category "AppArtifacts" -Severity "Medium" -Source $item.Name -Path $item.Path -Detail "Interesting file exists"
                }
            }
        }
        "Dir" {
            if (Test-Path $item.Path) {
                $dirList = Get-ChildItem -LiteralPath $item.Path -Force -Recurse -ErrorAction SilentlyContinue |
                    Where-Object {
                        -not (Test-IsReparsePoint $_) -and
                        -not $_.PSIsContainer -and
                        -not (Test-IsExcludedPathContains $_.FullName) -and
                        -not (Test-IsExcludedUserMicrosoftPath $_.FullName) -and
                        -not (Test-IsExcludedExtension $_.Extension) -and
                        -not (Test-IsExcludedFileName $_.Name)
                    } |
                    Select-Object FullName, Length, LastWriteTime |
                    Format-Table -AutoSize | Out-String
                Write-Info "`r`n[$($item.Name)]`r`n$($item.Path)`r`n$dirList"
                Add-Finding -Category "AppArtifacts" -Severity "Medium" -Source $item.Name -Path $item.Path -Detail "Interesting directory exists"
            }
        }
    }
}

# ---------- Admin: All-User Artifact Sweep ----------
Write-Section "Admin-Only All-User Artifact Sweep"
if ($IsAdmin) {
    try {
        $userDirs = Get-ChildItem "C:\Users" -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { -not (Test-IsReparsePoint $_) }

        foreach ($u in $userDirs) {
            $uPath = $u.FullName

            $adminArtifactPaths = @(
                (Join-Path $uPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"),
                (Join-Path $uPath "AppData\Roaming\WinSCP.ini"),
                (Join-Path $uPath "AppData\Roaming\FileZilla\sitemanager.xml"),
                (Join-Path $uPath "AppData\Roaming\FileZilla\recentservers.xml"),
                (Join-Path $uPath "AppData\Roaming\mRemoteNG\confCons.xml"),
                (Join-Path $uPath "AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings"),
                (Join-Path $uPath "Documents\Default.rdp"),
                (Join-Path $uPath ".aws\credentials"),
                (Join-Path $uPath ".aws\config"),
                (Join-Path $uPath ".git-credentials"),
                (Join-Path $uPath ".kube\config"),
                (Join-Path $uPath ".npmrc"),
                (Join-Path $uPath ".pypirc")
            )

            foreach ($ap in $adminArtifactPaths) {
                if ((Test-Path $ap) -and
                    (-not (Test-IsExcludedPath $ap)) -and
                    (-not (Test-IsExcludedPathContains $ap)) -and
                    (-not (Test-IsExcludedUserMicrosoftPath $ap)) -and
                    (-not (Test-IsExcludedFileName ([IO.Path]::GetFileName($ap)))) -and
                    (-not (Test-IsExcludedExtension ([IO.Path]::GetExtension($ap))))) {

                    Write-Info "[Admin Artifact] $ap"
                    Add-Finding -Category "AdminUserArtifacts" -Severity "Medium" -Source "Admin Sweep" -Path $ap -Detail "Interesting per-user artifact accessible as admin"

                    try {
                        $preview = Get-Content -LiteralPath $ap -ErrorAction SilentlyContinue | Select-Object -First 50 | Out-String
                        if ($preview) { Write-Info $preview }
                    } catch {}
                }
            }
        }
    } catch {}
} else {
    Write-Info "Skipped."
}

# ---------- VNC quick checks ----------
Write-Section "VNC Quick Registry Checks"
$vncKeys = @(
    "HKLM:\SOFTWARE\RealVNC",
    "HKLM:\SOFTWARE\TightVNC",
    "HKLM:\SOFTWARE\UltraVNC",
    "HKCU:\SOFTWARE\RealVNC",
    "HKCU:\SOFTWARE\TightVNC",
    "HKCU:\SOFTWARE\UltraVNC"
)

foreach ($vk in $vncKeys) {
    if (Test-Path $vk) {
        $vOut = Get-ItemProperty -Path $vk | Format-List * | Out-String
        Write-Info "`r`n[$vk]`r`n$vOut"
        Add-Finding -Category "VNC" -Severity "Medium" -Source "Registry" -Path $vk -Detail "VNC-related key exists"
    }
}

# ---------- High-Yield Directories ----------
Write-Section "High-Yield Directory Targets"

$targetPaths = @(
    (Join-Path $env:USERPROFILE "Desktop"),
    (Join-Path $env:USERPROFILE "Documents"),
    (Join-Path $env:USERPROFILE "Downloads"),
    (Join-Path $env:USERPROFILE "AppData\Roaming"),
    (Join-Path $env:USERPROFILE "AppData\Local"),
    "C:\Users\Public",
    "C:\ProgramData",
    "C:\Windows\Panther",
    "C:\Windows\System32\Sysprep",
    "C:\Windows.old",
    "C:\inetpub",
    "C:\xampp",
    "C:\Apache24",
    "C:\Apache",
    "C:\www",
    "C:\web",
    "C:\Scripts",
    "C:\Tools",
    "C:\Deploy",
    "C:\Install",
    "C:\Backups",
    "C:\Backup",
    "C:\Temp",
    "C:\Windows\Temp"
)

if ($IsAdmin) {
    $targetPaths += @(
        "C:\Users",
        "C:\Program Files",
        "C:\Program Files (x86)",
        "C:\Windows\Repair",
        "C:\Windows\System32\config",
        "C:\Windows\System32\config\RegBack",
        "C:\inetpub\history"
    )
}

if ($Deep) {
    $targetPaths += "C:\"
}

$targetPaths = $targetPaths | Select-Object -Unique

foreach ($tp in $targetPaths) {
    if (Test-Path $tp) {
        if ((Test-IsExcludedPath $tp) -or (Test-IsExcludedPathContains $tp) -or (Test-IsExcludedUserMicrosoftPath $tp)) {
            Write-Info "[-] Excluded: $tp"
        } else {
            Write-Info "[+] Exists: $tp"
        }
    }
}

# ---------- Other User Profile Probing ----------
Write-Section "Readable Other-User Profile Probing"

$otherUserDirs = @()
try {
    $otherUserDirs = Get-ChildItem "C:\Users" -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $_.FullName -ne $env:USERPROFILE -and
            -not (Test-IsReparsePoint $_)
        }
} catch {}

foreach ($u in $otherUserDirs) {
    $probePaths = @(
        (Join-Path $u.FullName "Desktop"),
        (Join-Path $u.FullName "Documents"),
        (Join-Path $u.FullName "Downloads"),
        (Join-Path $u.FullName "AppData\Roaming")
    )

    foreach ($pp in $probePaths) {
        if (Test-Path $pp) {
            if ((Test-IsExcludedPath $pp) -or (Test-IsExcludedPathContains $pp) -or (Test-IsExcludedUserMicrosoftPath $pp)) {
                Write-Info "[Excluded] $pp"
                continue
            }

            try {
                Get-ChildItem -LiteralPath $pp -Force -ErrorAction Stop | Select-Object -First 5 | Out-Null
                Write-Info "[Readable] $pp"
                Add-Finding -Category "ReadableProfiles" -Severity "Medium" -Source "ACL Probe" -Path $pp -Detail "Other-user path readable"
            } catch {
                Write-Info "[Denied/Empty] $pp"
            }
        }
    }
}

# ---------- Suspicious Filename Search ----------
Write-Section "Suspicious Filename Search"

$includeExt = @(
    ".txt",".ini",".xml",".config",".conf",".cfg",".json",".yml",".yaml",
    ".ps1",".bat",".cmd",".vbs",".rdp",".reg",".kdbx",".ppk",".pem",".key",
    ".sql",".zip",".7z",".rar",".bak",".old"
)

$nameRegex = '(pass|cred|secret|token|vpn|rdp|backup|backups|bak|config|connection|unattend|sysprep|install|deploy|script|db|sql|id_rsa|kdbx|ppk|pem|key|windows\.old|\.old$|old)'

foreach ($base in $targetPaths) {
    if (-not (Test-Path $base)) { continue }

    if ((Test-IsExcludedPath $base) -or (Test-IsExcludedPathContains $base) -or (Test-IsExcludedUserMicrosoftPath $base)) {
        Write-Info "`r`n--- Skipping excluded base path: $base ---"
        continue
    }

    Write-Info "`r`n--- Searching filenames in: $base ---"

    try {
        Get-ChildItem -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                -not $_.PSIsContainer -and
                -not (Test-IsReparsePoint $_) -and
                -not (Test-IsExcludedPath $_.FullName) -and
                -not (Test-IsExcludedPathContains $_.FullName) -and
                -not (Test-IsExcludedUserMicrosoftPath $_.FullName) -and
                -not (Test-IsExcludedFileName $_.Name) -and
                -not (Test-IsExcludedExtension $_.Extension) -and
                (
                    ($includeExt -contains $_.Extension.ToLower()) -or
                    ($_.Name -match $nameRegex) -or
                    ($_.DirectoryName -match '(?i)(backup|backups|bak|old|windows\.old)')
                )
            } |
            ForEach-Object {
                $line = "{0}`t{1}`t{2}" -f $_.LastWriteTime, $_.Length, $_.FullName
                Write-Info $line

                if (
                    ($_.Name -match $nameRegex) -or
                    ($_.DirectoryName -match '(?i)(backup|backups|bak|old|windows\.old)')
                ) {
                    Add-FilePreviewFinding -Category "SuspiciousFiles" -Path $_.FullName
                }
            }
    } catch {}
}

# ---------- Suspicious Directory Search (.old / backup / windows.old) ----------
Write-Section "Suspicious Directory Search"

$dirRegex = '(?i)(backup|backups|bak|old|windows\.old)'

foreach ($base in $targetPaths) {
    if (-not (Test-Path $base)) { continue }
    if ((Test-IsExcludedPath $base) -or (Test-IsExcludedPathContains $base) -or (Test-IsExcludedUserMicrosoftPath $base)) { continue }

    try {
        Get-ChildItem -LiteralPath $base -Recurse -Force -Directory -ErrorAction SilentlyContinue |
            Where-Object {
                -not (Test-IsReparsePoint $_) -and
                -not (Test-IsExcludedPath $_.FullName) -and
                -not (Test-IsExcludedPathContains $_.FullName) -and
                -not (Test-IsExcludedUserMicrosoftPath $_.FullName) -and
                ($_.Name -match $dirRegex)
            } |
            ForEach-Object {
                Write-Info "[Dir] $($_.FullName)"
                Add-Finding -Category "SuspiciousDirs" -Severity "Medium" -Source "DirectoryName" -Path $_.FullName -Detail "Directory name suggests old/backup content"
            }
    } catch {}
}

# ---------- Direct known files ----------
Write-Section "Direct Known File Checks"

$knownFiles = @(
    "C:\Windows\Panther\Unattend.xml",
    "C:\Windows\Panther\Unattended.xml",
    "C:\Windows\Panther\Unattend\Unattend.xml",
    "C:\Windows\System32\Sysprep\sysprep.xml",
    "C:\Windows\System32\Sysprep\Panther\Unattend.xml",
    "C:\Windows.old\Windows\Panther\Unattend.xml",
    "C:\Windows.old\Windows\Panther\Unattended.xml",
    "C:\Windows.old\Windows\System32\Sysprep\sysprep.xml",
    "C:\Windows.old\Windows\System32\Sysprep\Panther\Unattend.xml"
)

foreach ($kf in $knownFiles) {
    if (Test-Path $kf) {
        if ((Test-IsExcludedPath $kf) -or
            (Test-IsExcludedPathContains $kf) -or
            (Test-IsExcludedUserMicrosoftPath $kf) -or
            (Test-IsExcludedFileName ([IO.Path]::GetFileName($kf))) -or
            (Test-IsExcludedExtension ([IO.Path]::GetExtension($kf)))) {
            Write-Info "[-] Excluded known-file path: $kf"
            continue
        }

        Write-Info "[+] Found: $kf"
        Add-Finding -Category "Unattend" -Severity "High" -Source "KnownPath" -Path $kf -Detail "Known high-value unattended install file present"

        try {
            $content = Get-Content -LiteralPath $kf -ErrorAction SilentlyContinue | Select-Object -First 200 | Out-String
            Write-Info $content
        } catch {}
    }
}

# ---------- Admin: Extra High-Value File Checks ----------
Write-Section "Admin-Only Extra High-Value File Checks"
if ($IsAdmin) {
    $adminKnownFiles = @(
        "C:\Windows\System32\inetsrv\config\applicationHost.config",
        "C:\Windows.old\Windows\System32\inetsrv\config\applicationHost.config"
    )

    foreach ($akf in $adminKnownFiles) {
        if (Test-Path $akf) {
            if ((Test-IsExcludedPath $akf) -or
                (Test-IsExcludedPathContains $akf) -or
                (Test-IsExcludedUserMicrosoftPath $akf) -or
                (Test-IsExcludedFileName ([IO.Path]::GetFileName($akf))) -or
                (Test-IsExcludedExtension ([IO.Path]::GetExtension($akf)))) {
                continue
            }

            Write-Info "[+] Found admin file: $akf"
            Add-Finding -Category "AdminConfigs" -Severity "High" -Source "KnownPath" -Path $akf -Detail "Admin-readable high-value config file present"

            try {
                $preview = Get-Content -LiteralPath $akf -ErrorAction SilentlyContinue | Select-Object -First 200 | Out-String
                Write-Info $preview
            } catch {}
        }
    }
} else {
    Write-Info "Skipped."
}

# ---------- Content Search ----------
Write-Section "Content Search in Likely Text/Config Files"

$contentPatterns = @(
    'password',
    'passwd',
    'pwd',
    'apikey',
    'api_key',
    'connectionstring',
    'connstr',
    'defaultpassword',
    'autoadminlogon',
    'net use',
    'runas',
    'cmdkey',
    'ConvertTo-SecureString',
    'SecureString',
    'New-Object System.Management.Automation.PSCredential',
    'sqlcmd',
    'Invoke-Sqlcmd',
    'binddn',
    'bindpw'
)

$maxFileSizeBytes = 5MB
if ($Deep) { $maxFileSizeBytes = 15MB }

foreach ($base in $targetPaths) {
    if (-not (Test-Path $base)) { continue }

    if ((Test-IsExcludedPath $base) -or (Test-IsExcludedPathContains $base) -or (Test-IsExcludedUserMicrosoftPath $base)) {
        Write-Info "`r`n--- Skipping excluded content-search base path: $base ---"
        continue
    }

    Write-Info "`r`n--- Content search in: $base ---"

    try {
        Get-ChildItem -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object {
                -not $_.PSIsContainer -and
                -not (Test-IsReparsePoint $_) -and
                -not (Test-IsExcludedPath $_.FullName) -and
                -not (Test-IsExcludedPathContains $_.FullName) -and
                -not (Test-IsExcludedUserMicrosoftPath $_.FullName) -and
                -not (Test-IsExcludedFileName $_.Name) -and
                -not (Test-IsExcludedExtension $_.Extension) -and
                ($includeExt -contains $_.Extension.ToLower()) -and
                ($_.Length -lt $maxFileSizeBytes)
            } |
            ForEach-Object {
                $file = $_.FullName
                try {
                    $matches = Select-String -Path $file -Pattern $contentPatterns -SimpleMatch -ErrorAction SilentlyContinue

                    foreach ($m in $matches) {
                        if ($m.Matches.Count -eq 0) {
                            continue
                        }

                        $matchedValue = $m.Matches[0].Value
                        $snippet = Get-MatchSnippet -Line $m.Line -MatchedText $matchedValue -CharsAfter 30

                        if ([string]::IsNullOrEmpty($snippet)) {
                            continue
                        }

                        $detail = "Line $($m.LineNumber): [$matchedValue] -> $snippet"
                        $sev = Score-ContentHit -Line $m.Line

                        Add-Finding -Category "ContentHit" -Severity $sev -Source "Select-String" -Path $file -Detail $detail
                        Write-Info "$sev`t$file`t$detail"
                    }
                } catch {}
            }
    } catch {}
}

# ---------- Run / RunOnce quick check ----------
Write-Section "Run / RunOnce Registry Keys"

$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($rk in $runKeys) {
    if (Test-Path $rk) {
        $rOut = Get-ItemProperty -Path $rk | Format-List * | Out-String
        Write-Info "`r`n[$rk]`r`n$rOut"

        if ($rOut -match 'pass|cred|secret|token|\.ps1|\.bat|\.cmd|\.vbs|\.config|\.xml|\.ini|backup|old') {
            Add-Finding -Category "RunKeys" -Severity "Medium" -Source "Registry" -Path $rk -Detail "Interesting startup entry or script/config reference"
        }
    }
}

# ---------- Recent files / Shortcuts ----------
Write-Section "Recent Files / Shortcuts"

$recentPaths = @(
    (Join-Path $env:APPDATA "Microsoft\Windows\Recent"),
    (Join-Path $env:APPDATA "Microsoft\Windows\Recent\AutomaticDestinations")
)

foreach ($rp in $recentPaths) {
    if (Test-Path $rp) {
        if ((Test-IsExcludedPath $rp) -or (Test-IsExcludedPathContains $rp) -or (Test-IsExcludedUserMicrosoftPath $rp)) {
            Write-Info "[Excluded] $rp"
            continue
        }

        $rList = Get-ChildItem -LiteralPath $rp -Force -ErrorAction SilentlyContinue |
            Where-Object {
                -not (Test-IsReparsePoint $_) -and
                -not (Test-IsExcludedExtension $_.Extension) -and
                -not (Test-IsExcludedFileName $_.Name)
            } |
            Select-Object LastWriteTime, Length, FullName |
            Format-Table -AutoSize | Out-String

        Write-Info "`r`n[$rp]`r`n$rList"
        Add-Finding -Category "RecentFiles" -Severity "Low" -Source "Recent" -Path $rp -Detail "Recent files/jump lists present"
    }
}

Write-Section "Done"
Write-Info "Single output file: $OutFile"

Write-Host ""
Write-Host "Done."
Write-Host "Report: $OutFile"
