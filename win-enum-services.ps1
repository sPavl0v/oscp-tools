param(
    [string]$OutFile = ".\service_enum_report.txt"
)

# =========================
# Windows Service Enumeration (registry-based)
# No CIM / WMI dependency
# Read-only
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
        [string]$ServiceName,
        [string]$DisplayName,
        [string]$RunAs,
        [string]$BinaryPath,
        [string]$Vector,
        [string]$Detail
    )

    $obj = [PSCustomObject]@{
        ServiceName = $ServiceName
        DisplayName = $DisplayName
        RunAs       = $RunAs
        BinaryPath  = $BinaryPath
        Vector      = $Vector
        Detail      = $Detail
    }

    $global:Findings.Add($obj) | Out-Null
}

# ---------- Identity helpers ----------
function Test-IsAdmin {
    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentUserSid = $currentIdentity.User.Value
$currentGroupSids = @($currentIdentity.Groups | ForEach-Object { $_.Value })
$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity)
$IsAdmin = Test-IsAdmin

function Get-PrincipalSet {
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    [void]$set.Add($currentUserSid)
    foreach ($sid in $currentGroupSids) { [void]$set.Add($sid) }

    # Common SDDL aliases relevant to an interactive authenticated user
    [void]$set.Add("WD") # Everyone
    [void]$set.Add("AU") # Authenticated Users
    [void]$set.Add("IU") # Interactive
    [void]$set.Add("BU") # Builtin Users
    if ($IsAdmin) { [void]$set.Add("BA") } # Builtin Administrators

    return $set
}

$PrincipalSet = Get-PrincipalSet

# ---------- Generic helpers ----------
function Get-ServiceTypeName {
    param([int]$Type)

    $names = @()

    if ($Type -band 0x00000001) { $names += "KernelDriver" }
    if ($Type -band 0x00000002) { $names += "FileSystemDriver" }
    if ($Type -band 0x00000010) { $names += "Win32OwnProcess" }
    if ($Type -band 0x00000020) { $names += "Win32ShareProcess" }
    if ($Type -band 0x00000100) { $names += "Interactive" }

    if ($names.Count -eq 0) { return "Unknown" }
    return ($names -join ",")
}

function Get-StartTypeName {
    param([int]$Start)

    switch ($Start) {
        0 { "Boot" }
        1 { "System" }
        2 { "Automatic" }
        3 { "Manual" }
        4 { "Disabled" }
        default { "Unknown" }
    }
}

function Expand-PathString {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    try {
        return [Environment]::ExpandEnvironmentVariables($Value)
    } catch {
        return $Value
    }
}

function Get-ExecutableFromCommandLine {
    param([string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }

    $expanded = Expand-PathString $CommandLine
    $trimmed = $expanded.Trim()

    if ($trimmed.StartsWith('"')) {
        $m = [regex]::Match($trimmed, '^"([^"]+)"')
        if ($m.Success) { return $m.Groups[1].Value }
    }

    $mExe = [regex]::Match($trimmed, '^[^"]*?\.exe', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($mExe.Success) { return $mExe.Value.Trim() }

    $first = ($trimmed -split '\s+')[0]
    return $first.Trim('"')
}

function Get-CommandArgumentPaths {
    param([string]$CommandLine)

    $results = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return @() }

    $expanded = Expand-PathString $CommandLine

    foreach ($m in [regex]::Matches($expanded, '"([A-Za-z]:\\[^"]+|\\\\[^"]+)"')) {
        $results.Add($m.Groups[1].Value) | Out-Null
    }

    foreach ($m in [regex]::Matches($expanded, '([A-Za-z]:\\[^\s,;]+?\.(exe|dll|sys|bat|cmd|ps1|vbs|js|wsf|config|ini|xml|json|txt|psm1))', 'IgnoreCase')) {
        $results.Add($m.Groups[1].Value) | Out-Null
    }

    foreach ($m in [regex]::Matches($expanded, '(\\\\[^\s,;]+?\.(exe|dll|sys|bat|cmd|ps1|vbs|js|wsf|config|ini|xml|json|txt|psm1))', 'IgnoreCase')) {
        $results.Add($m.Groups[1].Value) | Out-Null
    }

    return $results | Select-Object -Unique
}

function Test-UnquotedServicePath {
    param([string]$ImagePath)

    if ([string]::IsNullOrWhiteSpace($ImagePath)) { return $false }

    $expanded = Expand-PathString $ImagePath
    $trimmed = $expanded.Trim()

    if ($trimmed.StartsWith('"')) { return $false }
    if ($trimmed -notmatch '\s') { return $false }

    $exe = Get-ExecutableFromCommandLine $trimmed
    if ([string]::IsNullOrWhiteSpace($exe)) { return $false }

    return ($exe -match '\s')
}

function Get-UnquotedHijackCandidates {
    param([string]$ImagePath)

    $candidates = New-Object System.Collections.Generic.List[string]

    if (-not (Test-UnquotedServicePath $ImagePath)) { return @() }

    $exe = Get-ExecutableFromCommandLine $ImagePath
    if ([string]::IsNullOrWhiteSpace($exe)) { return @() }

    $parts = $exe -split '\\'
    if ($parts.Count -lt 2) { return @() }

    for ($i = 1; $i -lt ($parts.Count - 1); $i++) {
        $segment = ($parts[0..$i] -join '\')
        if ($segment -match '\s') {
            $candidates.Add("$segment.exe") | Out-Null
        }
    }

    return $candidates | Select-Object -Unique
}

# ---------- ACL helpers ----------

function Test-FileSystemWritable-OLD {
    param([string]$Path, [switch]$IsDirectory)
    if (-not (Test-Path $Path)) { return $false }
    try {
        $acl = Get-Acl -LiteralPath $Path
        $allow = $false
        foreach ($rule in $acl.Access) {
            # Identity matching logic remains the same...
            $applies = $false
            $sid = try { $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $rule.IdentityReference.Value }
            if ($PrincipalSet.Contains($sid) -or $PrincipalSet.Contains($rule.IdentityReference.Value)) { $applies = $true }
            if (-not $applies) { continue }

            $rights = $rule.FileSystemRights
            
            # Define specific WRITE-ONLY bits that don't overlap with Read/Execute
            $writeBits = [System.Security.AccessControl.FileSystemRights]::WriteData -bor 
                         [System.Security.AccessControl.FileSystemRights]::AppendData -bor
                         [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles

            # Check for Modify or FullControl specifically
            $isWritable = (($rights -band $writeBits) -ne 0) -or 
                          ($rights -band [System.Security.AccessControl.FileSystemRights]::Modify) -eq [System.Security.AccessControl.FileSystemRights]::Modify -or
                          ($rights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq [System.Security.AccessControl.FileSystemRights]::FullControl

            if ($isWritable) {
                if ($rule.AccessControlType -eq "Deny") { return $false }
                $allow = $true
            }
        }
        return $allow
    } catch { return $false }
}

function Test-FileSystemWritable {
    param([string]$Path, [switch]$IsDirectory)
    if (-not (Test-Path $Path)) { return $false }
    try {
        $acl = Get-Acl -LiteralPath $Path
        $allow = $false
        foreach ($rule in $acl.Access) {
            $sid = try { $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $rule.IdentityReference.Value }
            if (-not ($PrincipalSet.Contains($sid) -or $PrincipalSet.Contains($rule.IdentityReference.Value))) { continue }

            $rights = [int]$rule.FileSystemRights
            
            # Actionable File Write Bits (WriteData=2, AppendData=4, WriteAttributes=16, Delete=65536, WriteDac=262144)
            $fileWrite = 0x2 -bor 0x4 -bor 0x10 -bor 0x10000 -bor 0x40000 -bor 0x80000
            
            # FullControl is 2032127
            if ((($rights -band $fileWrite) -ne 0) -or ($rights -eq 2032127)) {
                if ($rule.AccessControlType -eq "Deny") { return $false }
                $allow = $true
            }
        }
        return $allow
    } catch { return $false }
}

function Test-RegistryWritable {
    param([string]$RegistryPath)
    if (-not (Test-Path $RegistryPath)) { return $false }
    try {
        $acl = Get-Acl -Path $RegistryPath
        $allow = $false

        foreach ($rule in $acl.Access) {
            # Identity matching
            $sid = try { $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $rule.IdentityReference.Value }
            if (-not ($PrincipalSet.Contains($sid) -or $PrincipalSet.Contains($rule.IdentityReference.Value))) { continue }

            $rights = [int]$rule.RegistryRights
            
            # Actionable Write Bits (SetValue=2, CreateSubKey=4, Delete=65536, WriteDac=262144, WriteOwner=524288)
            # We EXCLUDE ReadControl (131072) which is what causes the false positive.
            $specificWrite = 0x2 -bor 0x4 -bor 0x10000 -bor 0x40000 -bor 0x80000
            
            # Check for specific write bits OR absolute FullControl (983103)
            if ((($rights -band $specificWrite) -ne 0) -or ($rights -eq 983103)) {
                if ($rule.AccessControlType -eq "Deny") { return $false }
                $allow = $true
            }
        }
        return $allow
    } catch { return $false }
}

# ---------- SDDL helpers ----------
function Parse-SddlAces {
    param([string]$Sddl)

    $aces = New-Object System.Collections.Generic.List[object]
    if ([string]::IsNullOrWhiteSpace($Sddl)) { return @() }

    foreach ($m in [regex]::Matches($Sddl, '\(([^)]+)\)')) {
        $aceText = $m.Groups[1].Value
        $parts = $aceText -split ';'
        if ($parts.Count -lt 6) { continue }

        $aces.Add([PSCustomObject]@{
            AceType = $parts[0]
            Rights  = $parts[2]
            Trustee = $parts[5]
        }) | Out-Null
    }

    return $aces
}

function Test-SddlRight {
    param(
        [string]$Sddl,
        [string]$RightCode
    )

    if ([string]::IsNullOrWhiteSpace($Sddl)) { return $false }

    $aces = Parse-SddlAces $Sddl
    $allow = $false

    foreach ($ace in $aces) {
        $applies = $false
        if ($PrincipalSet.Contains($ace.Trustee)) { $applies = $true }

        if (-not $applies) { continue }

        if ($ace.Rights -like "*$RightCode*") {
            if ($ace.AceType -eq "D") { return $false }
            if ($ace.AceType -eq "A") { $allow = $true }
        }
    }

    return $allow
}

function Get-ScSd {
    param([string]$Name)

    try {
        $out = & sc.exe sdshow $Name 2>$null | Out-String
        $sddl = ($out -split "`r?`n" | Where-Object { $_ -match '^D:' } | Select-Object -First 1)
        return $sddl
    } catch {
        return $null
    }
}

function Test-CanCreateService {
    $sddl = Get-ScSd "scmanager"
    if ([string]::IsNullOrWhiteSpace($sddl)) {
        return $IsAdmin
    }

    # SCMANAGER: DC ~= create service
    return (Test-SddlRight -Sddl $sddl -RightCode "DC")
}

function Get-ServiceDaclRights {
    param([string]$ServiceName)

    $sddl = Get-ScSd $ServiceName

    [PSCustomObject]@{
        Sddl            = $sddl
        CanStart        = (Test-SddlRight -Sddl $sddl -RightCode "RP")
        CanStop         = (Test-SddlRight -Sddl $sddl -RightCode "WP")
        CanChangeConfig = (Test-SddlRight -Sddl $sddl -RightCode "DC")
        CanDelete       = (Test-SddlRight -Sddl $sddl -RightCode "SD")
        CanWriteDac     = (Test-SddlRight -Sddl $sddl -RightCode "WD")
        CanWriteOwner   = (Test-SddlRight -Sddl $sddl -RightCode "WO")
    }
}

# ---------- Failure actions ----------
function Get-ServiceFailureActionsText {
    param([string]$ServiceName)

    try {
        $out = & sc.exe qfailure $ServiceName 2>$null | Out-String
        $clean = ($out -split "`r?`n" | Where-Object { $_.Trim() -ne "" }) -join "; "
        return $clean
    } catch {
        return $null
    }
}

# ---------- Begin ----------
Write-Section "Service Enumeration Baseline"
Write-Info "Date: $(Get-Date)"
Write-Info "User: $env:USERNAME"
Write-Info "Computer: $env:COMPUTERNAME"
Write-Info "Is admin: $IsAdmin"

$canCreateSvc = Test-CanCreateService
Write-Info "Can create service (heuristic): $canCreateSvc"

$servicesRoot = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
$serviceKeys = Get-ChildItem -Path $servicesRoot -ErrorAction SilentlyContinue

Write-Section "Enumerating Services From Registry"

foreach ($svcKey in $serviceKeys) {
    $svcName = $svcKey.PSChildName
    $svcRegPath = $svcKey.PSPath

    try {
        $props = Get-ItemProperty -Path $svcRegPath
    } catch {
        continue
    }

    $displayName = $props.DisplayName
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $svcName }

    $imagePath = $props.ImagePath
    $runAs = $props.ObjectName
    if ([string]::IsNullOrWhiteSpace($runAs)) { $runAs = "LocalSystem" }

    $typeName = Get-ServiceTypeName ([int]($props.Type))
    $startType = Get-StartTypeName ([int]($props.Start))

    if ($typeName -notmatch 'Win32') { continue }

    $exePath = Get-ExecutableFromCommandLine $imagePath
    $binaryExists = $false
    if ($exePath) { $binaryExists = Test-Path $exePath }

    $svcRegistryWritable = Test-RegistryWritable $svcRegPath

    $dacl = Get-ServiceDaclRights $svcName
    $canStartService = $dacl.CanStart
    $canStopService = $dacl.CanStop
    $canChangeConfig = $dacl.CanChangeConfig
    $canDeleteService = $dacl.CanDelete
    $canWriteDac = $dacl.CanWriteDac
    $canWriteOwner = $dacl.CanWriteOwner

    $binaryWritable = $false
    $binaryDirWritable = $false

    if ($exePath) {
        if (Test-Path $exePath) {
            $binaryWritable = Test-FileSystemWritable -Path $exePath
        }

        $parentDir = Split-Path -Parent $exePath
        if ($parentDir -and (Test-Path $parentDir)) {
            $binaryDirWritable = Test-FileSystemWritable -Path $parentDir -IsDirectory
        }
    }

    $brokenBinaryPath = $false
    if (-not [string]::IsNullOrWhiteSpace($exePath) -and -not $binaryExists) {
        $brokenBinaryPath = $true
    }

    # Explicit args from ImagePath
    $argPaths = @(Get-CommandArgumentPaths $imagePath | Where-Object { $_ -and ($_ -ne $exePath) } | Select-Object -Unique)
    $writableArgHits = New-Object System.Collections.Generic.List[string]

    foreach ($argPath in $argPaths) {
        $expandedArg = Expand-PathString $argPath

        if (Test-Path $expandedArg) {
            if (Test-FileSystemWritable -Path $expandedArg) {
                $writableArgHits.Add("Writable argument file: $expandedArg") | Out-Null
            }

            $argParent = Split-Path -Parent $expandedArg
            if ($argParent -and (Test-Path $argParent) -and (Test-FileSystemWritable -Path $argParent -IsDirectory)) {
                $writableArgHits.Add("Writable argument parent dir: $argParent") | Out-Null
            }
        } else {
            $argParent = Split-Path -Parent $expandedArg
            if ($argParent -and (Test-Path $argParent) -and (Test-FileSystemWritable -Path $argParent -IsDirectory)) {
                $writableArgHits.Add("Missing argument path with writable parent dir: $expandedArg") | Out-Null
            }
        }
    }

    # ServiceDll explicit handling for svchost/shared-process services
    $serviceDll = $null
    $serviceDllExists = $false
    $serviceDllWritable = $false
    $serviceDllDirWritable = $false
    $serviceDllBroken = $false

    $paramsPath = Join-Path $svcRegPath "Parameters"
    if (Test-Path $paramsPath) {
        try {
            $pprops = Get-ItemProperty -Path $paramsPath
            if ($pprops.ServiceDll) {
                $serviceDll = Expand-PathString $pprops.ServiceDll
                if ($serviceDll) {
                    $serviceDllExists = Test-Path $serviceDll
                    if ($serviceDllExists) {
                        $serviceDllWritable = Test-FileSystemWritable -Path $serviceDll
                        $dllParent = Split-Path -Parent $serviceDll
                        if ($dllParent -and (Test-Path $dllParent)) {
                            $serviceDllDirWritable = Test-FileSystemWritable -Path $dllParent -IsDirectory
                        }
                    } else {
                        $serviceDllBroken = $true
                        $dllParent = Split-Path -Parent $serviceDll
                        if ($dllParent -and (Test-Path $dllParent)) {
                            $serviceDllDirWritable = Test-FileSystemWritable -Path $dllParent -IsDirectory
                        }
                    }
                }
            }
        } catch {}
    }

    # Generic referenced registry string paths
    $referencedPaths = New-Object System.Collections.Generic.List[string]

    foreach ($prop in $props.PSObject.Properties) {
        if ($prop.Value -is [string]) {
            foreach ($p in (Get-CommandArgumentPaths $prop.Value)) {
                if (-not [string]::IsNullOrWhiteSpace($p)) {
                    $referencedPaths.Add($p) | Out-Null
                }
            }
        }
    }

    if (Test-Path $paramsPath) {
        try {
            $pprops = Get-ItemProperty -Path $paramsPath
            foreach ($prop in $pprops.PSObject.Properties) {
                if ($prop.Value -is [string]) {
                    foreach ($p in (Get-CommandArgumentPaths $prop.Value)) {
                        if (-not [string]::IsNullOrWhiteSpace($p)) {
                            $referencedPaths.Add($p) | Out-Null
                        }
                    }
                }
            }
        } catch {}
    }

    $referencedPaths = $referencedPaths | Select-Object -Unique
    $refWritableHits = New-Object System.Collections.Generic.List[string]

    foreach ($refPath in $referencedPaths) {
        try {
            $expandedRef = Expand-PathString $refPath
            if ($expandedRef -eq $exePath) { continue }
            if ($serviceDll -and ($expandedRef -eq $serviceDll)) { continue }

            if (Test-Path $expandedRef) {
                if (Test-FileSystemWritable -Path $expandedRef) {
                    $refWritableHits.Add("Writable referenced file: $expandedRef") | Out-Null
                }

                $refParent = Split-Path -Parent $expandedRef
                if ($refParent -and (Test-Path $refParent) -and (Test-FileSystemWritable -Path $refParent -IsDirectory)) {
                    $refWritableHits.Add("Writable referenced parent dir: $refParent") | Out-Null
                }
            } else {
                $refParent = Split-Path -Parent $expandedRef
                if ($refParent -and (Test-Path $refParent) -and (Test-FileSystemWritable -Path $refParent -IsDirectory)) {
                    $refWritableHits.Add("Missing referenced path with writable parent dir: $expandedRef") | Out-Null
                }
            }
        } catch {}
    }

    $unquoted = Test-UnquotedServicePath $imagePath
    $unquotedCandidates = @()
    $unquotedWritable = New-Object System.Collections.Generic.List[string]

    if ($unquoted) {
        $unquotedCandidates = Get-UnquotedHijackCandidates $imagePath
        foreach ($cand in $unquotedCandidates) {
            $candParent = Split-Path -Parent $cand
            if ($candParent -and (Test-Path $candParent) -and (Test-FileSystemWritable -Path $candParent -IsDirectory)) {
                $unquotedWritable.Add($cand) | Out-Null
            }
        }
    }

    $failureActionsText = Get-ServiceFailureActionsText $svcName
    $hasFailureActions = -not [string]::IsNullOrWhiteSpace($failureActionsText)

    $vectors = New-Object System.Collections.Generic.List[string]

    if ($svcRegistryWritable) { $vectors.Add("Writable service registry key") | Out-Null }
    if ($canChangeConfig) { $vectors.Add("Can change service config") | Out-Null }
    if ($canStartService) { $vectors.Add("Can start service") | Out-Null }
    if ($canStopService) { $vectors.Add("Can stop service") | Out-Null }
    if ($canDeleteService) { $vectors.Add("Can delete service") | Out-Null }
    if ($canWriteDac) { $vectors.Add("Can write service DACL") | Out-Null }
    if ($canWriteOwner) { $vectors.Add("Can take ownership of service") | Out-Null }
    if ($canCreateSvc) { $vectors.Add("Can create service as SYSTEM") | Out-Null }

    if ($binaryWritable) { $vectors.Add("Writable service binary") | Out-Null }
    if ($binaryDirWritable) { $vectors.Add("Writable service binary directory") | Out-Null }
    if ($brokenBinaryPath) { $vectors.Add("Missing/broken service binary path") | Out-Null }

    if ($unquoted) {
        if ($unquotedWritable.Count -gt 0) {
            $vectors.Add("Unquoted service path with writable hijack location") | Out-Null
        } else {
            $vectors.Add("Unquoted service path") | Out-Null
        }
    }

    if ($writableArgHits.Count -gt 0) {
        $vectors.Add("Writable argument path") | Out-Null
    }

    if ($serviceDll) {
        if ($serviceDllWritable) { $vectors.Add("Writable ServiceDll") | Out-Null }
        if ($serviceDllDirWritable) { $vectors.Add("Writable ServiceDll directory") | Out-Null }
        if ($serviceDllBroken) { $vectors.Add("Missing/broken ServiceDll path") | Out-Null }
    }

    if ($refWritableHits.Count -gt 0) {
        $vectors.Add("Writable referenced config/module/script path") | Out-Null
    }

    # If no vectors were found at all, skip the service
    if ($vectors.Count -eq 0) { continue }

    # Filter out purely operational rights (Start/Stop) 
    # We only care about these if they accompany a real vulnerability (like a writable binary)
    $dangerousVectors = $vectors | Where-Object { 
        $_ -ne "Can start service" -and 
        $_ -ne "Can stop service" 
    }

    # If the findings consist ONLY of Start, Stop, or both, skip this service
    if ($dangerousVectors.Count -eq 0) {
        continue
    }

    Write-Section "Suspicious Service"
    Write-Info "ServiceName    : $svcName"
    Write-Info "DisplayName    : $displayName"
    Write-Info "RunAs          : $runAs"
    Write-Info "Type           : $typeName"
    Write-Info "StartType      : $startType"
    Write-Info "ImagePath      : $imagePath"
    Write-Info "Binary         : $exePath"
    Write-Info "BinaryExists   : $binaryExists"
    Write-Info "CanStart       : $canStartService"
    Write-Info "CanStop        : $canStopService"
    Write-Info "CanChangeCfg   : $canChangeConfig"
    Write-Info "CanDelete      : $canDeleteService"
    Write-Info "CanWriteDac    : $canWriteDac"
    Write-Info "CanWriteOwner  : $canWriteOwner"
    Write-Info "CanCreateSvc   : $canCreateSvc"
    Write-Info "Vectors        : $($vectors -join '; ')"

    if ($hasFailureActions) {
        Write-Info "FailureActions : $failureActionsText"
    }

    if ($svcRegistryWritable) {
        Write-Info "Detail         : Service registry key appears writable: $svcRegPath"
        Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "WritableRegistry" -Detail $svcRegPath
    }

    if ($canChangeConfig) {
        Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "CanChangeConfig" -Detail "Heuristic from service security descriptor"
    }

    if ($canStartService) {
        Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "CanStartService" -Detail "Heuristic from service security descriptor"
    }

    if ($canStopService) {
        Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "CanStopService" -Detail "Heuristic from service security descriptor"
    }

    if ($canDeleteService) {
        Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "CanDeleteService" -Detail "Heuristic from service security descriptor"
    }

    if ($canWriteDac) {
        Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "CanWriteDac" -Detail "Heuristic from service security descriptor"
    }

    if ($canWriteOwner) {
        Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "CanWriteOwner" -Detail "Heuristic from service security descriptor"
    }

    if ($canCreateSvc) {
        Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "CanCreateService" -Detail "Heuristic from SCM security descriptor"
    }

    if ($binaryWritable) {
        Write-Info "Detail         : Service binary appears writable: $exePath"
        Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "WritableBinary" -Detail $exePath
    }

    if ($binaryDirWritable) {
        $parentDir = Split-Path -Parent $exePath
        Write-Info "Detail         : Service binary directory appears writable: $parentDir"
        Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "WritableBinaryDir" -Detail $parentDir
    }

    if ($brokenBinaryPath) {
        Write-Info "Detail         : Service binary path is missing/broken: $exePath"
        Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "BrokenBinaryPath" -Detail $exePath
    }

    if ($unquoted) {
        Write-Info "Detail         : Unquoted service path detected"
        if ($unquotedCandidates.Count -gt 0) {
            Write-Info "Candidates     : $($unquotedCandidates -join '; ')"
        }
        if ($unquotedWritable.Count -gt 0) {
            Write-Info "Hijackable     : $($unquotedWritable -join '; ')"
        }
        Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "UnquotedPath" -Detail ($unquotedCandidates -join '; ')
    }

    foreach ($hit in $writableArgHits) {
        Write-Info "Detail         : $hit"
        Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "WritableArgumentPath" -Detail $hit
    }

    if ($serviceDll) {
        Write-Info "ServiceDll     : $serviceDll"
        Write-Info "ServiceDllExists: $serviceDllExists"

        if ($serviceDllWritable) {
            Write-Info "Detail         : ServiceDll appears writable: $serviceDll"
            Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "WritableServiceDll" -Detail $serviceDll
        }

        if ($serviceDllDirWritable) {
            $dllParent = Split-Path -Parent $serviceDll
            Write-Info "Detail         : ServiceDll directory appears writable: $dllParent"
            Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "WritableServiceDllDir" -Detail $dllParent
        }

        if ($serviceDllBroken) {
            Write-Info "Detail         : ServiceDll path is missing/broken: $serviceDll"
            Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "BrokenServiceDllPath" -Detail $serviceDll
        }
    }

    foreach ($hit in $refWritableHits) {
        Write-Info "Detail         : $hit"
        Add-Finding -ServiceName $svcName -DisplayName $displayName -RunAs $runAs -BinaryPath $exePath -Vector "WritableReferencedPath" -Detail $hit
    }
}

Write-Section "Done"
Write-Info "Report: $OutFile"

Write-Host ""
Write-Host "Done."
Write-Host "Report: $OutFile"
