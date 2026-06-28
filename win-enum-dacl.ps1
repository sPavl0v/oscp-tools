param(
    [string]$User,
    [string]$Pass,
    [string]$Domain,  # Removed the hardcoded default
    [string]$Server,  # Removed the hardcoded default
    [string]$TargetIdentity = $null,
    [switch]$HideNoise = $true
)

# 1. Configuration
$RightsRegex = "GenericAll|WriteDacl|WriteOwner|GenericWrite|WriteProperty|AddMember|ForceChangePassword|AllExtendedRights"
$NoiseList = @(
    "NT AUTHORITY\SYSTEM", "Local System", "Domain Admins", "NT AUTHORITY\SELF", 
    "Principal Self", "Administrator", "Enterprise Admins", "Domain Controllers", 
    "Exchange Windows Permissions",
    "Terminal Server License Servers", "Cert Publishers", "Pre-Windows 2000 Compatible Access",
    "BUILTIN\Account Operators", "Creator Owner"
)

Write-Host "[*] PowerView DACL Reconnaissance (Robust Version)" -ForegroundColor Cyan

# 2. Authentication and Parameter Splatting
$AclParams = @{
    ResolveGUIDs = $true
}

# Dynamically add parameters ONLY if they are explicitly passed into the script
if ($Domain) { $AclParams["Domain"] = $Domain }
if ($Server) { $AclParams["Server"] = $Server }
if ($TargetIdentity) { $AclParams["Identity"] = $TargetIdentity }

if ($User -and $Pass) {
    $secPass = $Pass | ConvertTo-SecureString -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($User, $secPass)
    $AclParams["Credential"] = $cred
}

Write-Host ("=" * 60)

# 3. Execution
try {
    # Using the dynamically built hash table
    Get-DomainObjectAcl @AclParams | ForEach-Object {
        $Who = Convert-SidToName $_.SecurityIdentifier
        $Rights = $_.ActiveDirectoryRights
        $Target = $_.ObjectDN
        
        $IsInteresting = $Rights -match $RightsRegex
        $IsNoise = $false
        
        if ($HideNoise) {
            # CIRCUIT BREAKER 1: Skip if Who is null/blank
            if ([string]::IsNullOrWhiteSpace($Who)) { return } 

            # CIRCUIT BREAKER 2: Skip if explicitly in noise list
            foreach ($NoiseItem in $NoiseList) {
                if ($Who -like "*$NoiseItem*") { $IsNoise = $true; break }
            }
            if ($IsNoise) { return }

            # CIRCUIT BREAKER 3: Skip if user has rights over themselves
            if ($Who -and ($Target -match [regex]::Escape($Who))) { return }
            
            # CIRCUIT BREAKER 4: Skip minor property noise
            if ($Rights -eq "ReadProperty, WriteProperty") { return }
        }

        if ($IsInteresting) {
            Write-Host "Who:        $Who" -ForegroundColor Yellow
            Write-Host "Target:     $Target" -ForegroundColor White
            Write-Host "Permission: $Rights" -ForegroundColor Green
            Write-Host ("-" * 40)
        }
    }
} catch {
    Write-Host "[-] LDAP Query Failed: $_" -ForegroundColor Red
}
