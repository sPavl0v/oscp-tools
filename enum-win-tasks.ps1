# enum-win-tasks-list.ps1
# Plain schtasks parser, no CIM/WMI

param(
    [string]$OutputFile = ".\tasks_review.txt"
)

function Write-Out {
    param([string]$Text)
    $Text | Out-File -FilePath $OutputFile -Append -Encoding utf8
}

function Expand-EnvPath {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $Text
    }

    try {
        return [Environment]::ExpandEnvironmentVariables($Text)
    } catch {
        return $Text
    }
}

function Get-TargetPath {
    param([string]$TaskRunRaw)

    if ([string]::IsNullOrWhiteSpace($TaskRunRaw)) {
        return $null
    }

    $taskRun = Expand-EnvPath $TaskRunRaw

    if ($taskRun -match '^\s*COM handler\s*$') {
        return $null
    }

    # quoted absolute path first
    if ($taskRun -match '^\s*"([^"]+\.(exe|ps1|bat|cmd|vbs|js))"') {
        return $matches[1]
    }

    # unquoted absolute path first token
    if ($taskRun -match '^\s*([A-Za-z]:\\[^\r\n]*?\.(exe|ps1|bat|cmd|vbs|js))(?=\s|$)') {
        return $matches[1]
    }

    # wrapped interpreter with script in args
    if ($taskRun -match '([A-Za-z]:\\[^\r\n"]+\.(ps1|bat|cmd|vbs|js))') {
        return $matches[1]
    }

    # relative exe like BthUdTask.exe -> not useful for file icacls unless resolved manually
    if ($taskRun -match '^\s*([^\s"]+\.(exe|ps1|bat|cmd|vbs|js))(?=\s|$)') {
        return $matches[1]
    }

    return $null
}

function Is-InterestingTask {
    param(
        [string]$TaskName,
        [string]$TaskRunRaw,
        [string]$RunAsUser
    )

    if ([string]::IsNullOrWhiteSpace($TaskRunRaw)) {
        return $false
    }

    $taskRun = Expand-EnvPath $TaskRunRaw

    if ($taskName -like "\Microsoft\*") {
        return $false
    }

    if ($taskRun -match '^\s*COM handler\s*$') {
        return $false
    }

    $isScript = $taskRun -match '\.(ps1|bat|cmd|vbs|js)(?=\s|$|")'
    $isUserPath = $taskRun -match '^[\s"]*[A-Za-z]:\\Users\\'
    $isProgramData = $taskRun -match '^[\s"]*[A-Za-z]:\\ProgramData\\'
    $isTemp = $taskRun -match '^[\s"]*[A-Za-z]:\\(Temp|tmp)\\'
    $isCustomNonWindows = $taskRun -match '^[\s"]*[A-Za-z]:\\' -and $taskRun -notmatch '^[\s"]*[A-Za-z]:\\Windows\\'
    $isSystemUser = $RunAsUser -match 'SYSTEM'

    # obvious Windows noise
    $isWindowsBinary = $taskRun -match '^[\s"]*[A-Za-z]:\\Windows\\'
    $isSystem32 = $taskRun -match '^[\s"]*[A-Za-z]:\\Windows\\System32\\'
    $isProgramFiles = $taskRun -match '^[\s"]*[A-Za-z]:\\Program Files( \(x86\))?\\'

    if ($isScript -or $isUserPath -or $isProgramData -or $isTemp -or $isCustomNonWindows) {
        return $true
    }

    # SYSTEM tasks are only interesting if they are not standard Windows paths
    if ($isSystemUser -and -not $isWindowsBinary) {
        return $true
    }

    # Some Program Files tasks may still be worth checking, but only if SYSTEM
    if ($isSystemUser -and $isProgramFiles) {
        return $true
    }

    # SYSTEM + system32 only = ignore
    if ($isSystemUser -and $isSystem32) {
        return $false
    }

    return $false
}

function Test-LikelyWritableFromIcacls {
    param([string[]]$Lines)

    if (-not $Lines) {
        return $false
    }

    foreach ($line in $Lines) {
        if (
            $line -match 'Everyone:.*\((F|M|W)\)' -or
            $line -match 'BUILTIN\\Users:.*\((F|M|W)\)' -or
            $line -match 'Authenticated Users:.*\((F|M|W)\)' -or
            $line -match 'NT AUTHORITY\\INTERACTIVE:.*\((F|M|W)\)' -or
            $line -match '\\Users:.*\((F|M|W)\)'
        ) {
            return $true
        }
    }

    return $false
}

function Flush-Task {
    param(
        [string]$TaskName,
        [string]$TaskRun,
        [string]$RunAsUser
    )

    if ([string]::IsNullOrWhiteSpace($TaskName) -and [string]::IsNullOrWhiteSpace($TaskRun) -and [string]::IsNullOrWhiteSpace($RunAsUser)) {
        return
    }

    if (-not (Is-InterestingTask -TaskName $TaskName -TaskRunRaw $TaskRun -RunAsUser $RunAsUser)) {
        return
    }

    $expandedTaskRun = Expand-EnvPath $TaskRun
    $targetPath = Get-TargetPath -TaskRunRaw $TaskRun
    $folderPath = $null

    if ($targetPath -and ($targetPath -match '^[A-Za-z]:\\')) {
        try { $folderPath = Split-Path -Path $targetPath -Parent } catch {}
    }

    $fileExists = $false
    $folderExists = $false
    $fileIcacls = @()
    $folderIcacls = @()

    if ($targetPath -and (Test-Path -LiteralPath $targetPath)) {
        $fileExists = $true
        $fileIcacls = icacls $targetPath 2>$null
    }

    if ($folderPath -and (Test-Path -LiteralPath $folderPath)) {
        $folderExists = $true
        $folderIcacls = icacls $folderPath 2>$null
    }

    $fileWritable = Test-LikelyWritableFromIcacls $fileIcacls
    $folderWritable = Test-LikelyWritableFromIcacls $folderIcacls

    Write-Out "TaskName      : $TaskName"
    Write-Out "RunAsUser     : $RunAsUser"
    Write-Out "Task To Run   : $TaskRun"
    Write-Out "Expanded Run  : $expandedTaskRun"
    Write-Out "TargetPath    : $targetPath"
    Write-Out "FolderPath    : $folderPath"
    Write-Out "FileExists    : $(if ($fileExists) { 'YES' } else { 'NO / NOT PARSED / RELATIVE' })"
    Write-Out "FolderExists  : $(if ($folderExists) { 'YES' } else { 'NO / NOT PARSED / RELATIVE' })"
    Write-Out "FileWritable? : $(if ($fileWritable) { 'LIKELY YES' } else { 'NO / UNKNOWN' })"
    Write-Out "DirWritable?  : $(if ($folderWritable) { 'LIKELY YES' } else { 'NO / UNKNOWN' })"

    if ($fileIcacls.Count -gt 0) {
        Write-Out "---- icacls file ----"
        $fileIcacls | Out-File -FilePath $OutputFile -Append -Encoding utf8
    }

    if ($folderIcacls.Count -gt 0) {
        Write-Out "---- icacls folder ----"
        $folderIcacls | Out-File -FilePath $OutputFile -Append -Encoding utf8
    }

    if ($fileWritable -or $folderWritable) {
        Write-Out "*** REVIEW THIS TASK MANUALLY ***"
    }

    Write-Out ""
}

# reset output
"" | Out-File -FilePath $OutputFile -Encoding utf8
Write-Out "========== Scheduled Tasks Review (LIST parser) =========="
Write-Out "Host: $env:COMPUTERNAME"
Write-Out "Date: $(Get-Date)"
Write-Out ""

$lines = schtasks /query /fo LIST /v 2>$null

if (-not $lines) {
    Write-Host "[-] schtasks returned no data"
    exit
}

$currentTaskName = $null
$currentTaskRun = $null
$currentRunAsUser = $null

foreach ($line in $lines) {
    if ($line -match '^TaskName:\s*(.+)$') {
        # flush previous task before starting a new one
        Flush-Task -TaskName $currentTaskName -TaskRun $currentTaskRun -RunAsUser $currentRunAsUser
        $currentTaskName = $matches[1].Trim()
        $currentTaskRun = $null
        $currentRunAsUser = $null
        continue
    }

    if ($line -match '^Task To Run:\s*(.*)$') {
        $currentTaskRun = $matches[1].Trim()
        continue
    }

    if ($line -match '^Run As User:\s*(.*)$') {
        $currentRunAsUser = $matches[1].Trim()
        continue
    }
}

# flush last task
Flush-Task -TaskName $currentTaskName -TaskRun $currentTaskRun -RunAsUser $currentRunAsUser

Write-Host "[+] Done. Review file: $OutputFile"
