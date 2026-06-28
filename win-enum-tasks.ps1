param(
    [string]$OutFile = ".\task_enum_report.txt"
)

# =========================
# Windows Scheduled Task Enumeration
# COM Object based (Schedule.Service)
# No CIM / WMI / ScheduledTasks module dependency
# UTF-8 output for Windows/Linux readability
# =========================

$ErrorActionPreference = "SilentlyContinue"

# ---------- Setup ----------
$parent = Split-Path -Parent $OutFile
if ($parent -and -not (Test-Path $parent)) {
    New-Item -ItemType Directory -Path $parent | Out-Null
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutFile, "", $utf8NoBom)

$global:Findings = New-Object System.Collections.Generic.List[Object]

function Append-Utf8Text {
    param([string]$Text)
    if ($null -eq $Text) { $Text = "" }
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
    if ($null -eq $Text) { $Text = "" }
    Write-Host $Text
    Append-Utf8Text ($Text + "`r`n")
}

function Add-Finding {
    param(
        [string]$TaskName,
        [string]$RunAs,
        [string]$Vector,
        [string]$Detail
    )
    $obj = [PSCustomObject]@{
        TaskName = $TaskName
        RunAs    = $RunAs
        Vector   = $Vector
        Detail   = $Detail
    }
    $global:Findings.Add($obj) | Out-Null
}

# ---------- Identity Helpers ----------
function Test-IsAdmin {
    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentUserSid = $currentIdentity.User.Value
$currentGroupSids = @($currentIdentity.Groups | ForEach-Object { $_.Value })
$IsAdmin = Test-IsAdmin

function Get-PrincipalSet {
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    [void]$set.Add($currentUserSid)
    foreach ($sid in $currentGroupSids) { [void]$set.Add($sid) }
    [void]$set.Add("WD") # Everyone
    [void]$set.Add("AU") # Authenticated Users
    [void]$set.Add("IU") # Interactive
    [void]$set.Add("BU") # Builtin Users
    if ($IsAdmin) { [void]$set.Add("BA") } # Builtin Administrators
    return $set
}
$PrincipalSet = Get-PrincipalSet

# ---------- File System / String Helpers ----------
function Expand-PathString {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try { return [Environment]::ExpandEnvironmentVariables($Value) } catch { return $Value }
}

function Get-CommandArgumentPaths {
    param([string]$CommandLine)
    $results = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return @() }
    $expanded = Expand-PathString $CommandLine
    foreach ($m in [regex]::Matches($expanded, '"([A-Za-z]:\\[^"]+|\\\\[^"]+)"')) {
        $results.Add($m.Groups[1].Value) | Out-Null
    }
    foreach ($m in [regex]::Matches($expanded, '([A-Za-z]:\\[^\s,;]+?\.(exe|dll|bat|cmd|ps1|vbs|js|wsf|config|ini|xml|json|txt|psm1))', 'IgnoreCase')) {
        $results.Add($m.Groups[1].Value) | Out-Null
    }
    return $results | Select-Object -Unique
}

function Test-FileSystemWritable {
    param([string]$Path, [switch]$IsDirectory)
    if (-not (Test-Path $Path)) { return $false }
    try {
        $acl = Get-Acl -LiteralPath $Path
        $allow = $false
        foreach ($rule in $acl.Access) {
            $sid = try { $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } 
                   catch { $rule.IdentityReference.Value }

            if (-not ($PrincipalSet.Contains($sid) -or $PrincipalSet.Contains($rule.IdentityReference.Value))) { continue }

            $rights = [int]$rule.FileSystemRights
            
            # Actionable File Write Bits (WriteData=2, AppendData=4, WriteAttributes=16, Delete=65536, WriteDac=262144, WriteOwner=524288)
            $fileWrite = 0x2 -bor 0x4 -bor 0x10 -bor 0x10000 -bor 0x40000 -bor 0x80000
            
            if ((($rights -band $fileWrite) -ne 0) -or ($rights -eq 2032127)) {
                if ($rule.AccessControlType -eq "Deny") { return $false }
                $allow = $true
            }
        }
        return $allow
    } catch { return $false }
}

function Test-UnquotedTaskPath {
    param([string]$ImagePath)
    if ([string]::IsNullOrWhiteSpace($ImagePath)) { return $false }
    $expanded = Expand-PathString $ImagePath
    $trimmed = $expanded.Trim()
    if ($trimmed.StartsWith('"')) { return $false }
    if ($trimmed -notmatch '\s') { return $false }
    $mExe = [regex]::Match($trimmed, '^[^"]*?\.exe', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($mExe.Success) { return ($mExe.Value.Trim() -match '\s') }
    return $false
}

function Get-TriggerString {
    param([int]$TriggerType)
    switch ($TriggerType) {
        1 { "Event" }
        2 { "Time (Scheduled)" }
        3 { "Daily" }
        4 { "Weekly" }
        5 { "Monthly" }
        6 { "Monthly Day of Week" }
        7 { "On Idle" }
        8 { "On Task Registration" }
        9 { "On Boot" }
        10 { "On Logon" }
        11 { "On Session State Change" }
        12 { "Custom" }
        default { "Unknown ($TriggerType)" }
    }
}

# ---------- Begin ----------
Write-Section "Scheduled Task Enumeration Baseline"
Write-Info "Date: $(Get-Date)"
Write-Info "User: $env:USERNAME"
Write-Info "Computer: $env:COMPUTERNAME"

try {
    $sch = New-Object -ComObject Schedule.Service
    $sch.Connect()
    $root = $sch.GetFolder("\")
} catch {
    Write-Info "[-] Failed to connect to Schedule.Service COM object."
    exit
}

Write-Section "Enumerating Tasks"

$queue = New-Object System.Collections.Generic.Queue[System.__ComObject]
$queue.Enqueue($root)

while ($queue.Count -gt 0) {
    $folder = $queue.Dequeue()
    try {
        $subfolders = $folder.GetFolders(0)
        foreach ($sf in $subfolders) { $queue.Enqueue($sf) }
    } catch {}

    $tasks = $null
    try { $tasks = $folder.GetTasks(0) } catch {}
    if (-not $tasks) { continue }

    foreach ($task in $tasks) {
        if ($task.Path -like "\Microsoft\Windows\*") { continue }
        $vectors = New-Object System.Collections.Generic.List[string]
        $taskPath = $task.Path
        $taskName = $task.Name
        
        $runAs = "Unknown"
        try { 
            $runAs = $task.Definition.Principal.UserId 
            if ([string]::IsNullOrWhiteSpace($runAs)) { $runAs = "SYSTEM/Default" }
        } catch {}

        $actions = $null
        try { $actions = $task.Definition.Actions } catch {}
        if (-not $actions) { continue }

        foreach ($action in $actions) {
            if ($action.Type -ne 0) { continue } 

            $exePath = Expand-PathString $action.Path
            $argsStr = Expand-PathString $action.Arguments

            $binaryWritable = $false
            $binaryDirWritable = $false
            $unquoted = $false
            $writableArgsHits = New-Object System.Collections.Generic.List[string]

            if (-not [string]::IsNullOrWhiteSpace($exePath)) {
                if (Test-Path $exePath) {
                    $binaryWritable = Test-FileSystemWritable -Path $exePath
                }
                $parentDir = Split-Path -Parent $exePath
                if ($parentDir -and (Test-Path $parentDir)) {
                    $binaryDirWritable = Test-FileSystemWritable -Path $parentDir -IsDirectory
                }
                $unquoted = Test-UnquotedTaskPath $exePath
            }

            if (-not [string]::IsNullOrWhiteSpace($argsStr)) {
                $argPaths = Get-CommandArgumentPaths $argsStr
                foreach ($ap in $argPaths) {
                    if (Test-Path $ap) {
                        if (Test-FileSystemWritable -Path $ap) {
                            $writableArgsHits.Add("Writable argument file: $ap") | Out-Null
                        }
                    } else {
                        $apParent = Split-Path -Parent $ap
                        if ($apParent -and (Test-Path $apParent) -and (Test-FileSystemWritable -Path $apParent -IsDirectory)) {
                            $writableArgsHits.Add("Missing argument file in writable dir: $ap") | Out-Null
                        }
                    }
                }
            }

            if ($binaryWritable) { $vectors.Add("Writable binary ($exePath)") | Out-Null }
            if ($binaryDirWritable) { $vectors.Add("Writable binary dir ($parentDir)") | Out-Null }
            if ($unquoted) { $vectors.Add("Unquoted executable path ($exePath)") | Out-Null }
            foreach ($hit in $writableArgsHits) { $vectors.Add($hit) | Out-Null }
        }

        if ($vectors.Count -eq 0) { continue }

        $triggersStr = "None/Manual"
        try {
            $tList = New-Object System.Collections.Generic.List[string]
            foreach ($t in $task.Definition.Triggers) {
                # FIXED: Wrapped method argument in extra parentheses
                $triggerName = Get-TriggerString ($t.Type)
                $tList.Add($triggerName) | Out-Null
            }
            if ($tList.Count -gt 0) { $triggersStr = ($tList -join ", ") }
        } catch {}

        Write-Section "Vulnerable Task Found"
        Write-Info "TaskName       : $taskName"
        Write-Info "TaskPath       : $taskPath"
        Write-Info "RunAs          : $runAs"
        Write-Info "Triggers       : $triggersStr"
        Write-Info "Vectors        : $($vectors -join '; ')"
        
        foreach ($action in $actions) {
            if ($action.Type -eq 0) {
                Write-Info "Action Binary  : $($action.Path)"
                Write-Info "Action Args    : $($action.Arguments)"
            }
        }

        foreach ($v in $vectors) {
            Add-Finding -TaskName $taskName -RunAs $runAs -Vector $v -Detail "Found via COM object enumeration"
        }
    }
}

Write-Section "Done"
Write-Info "Report: $OutFile"
Write-Host "`r`nDone. Vulnerable tasks reported to $OutFile"
