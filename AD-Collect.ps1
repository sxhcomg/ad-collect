<#
.SYNOPSIS
    Read-only on-prem Active Directory configuration collector.

.DESCRIPTION
    Runs the checks from the AD Hardening Checklist and writes the raw answers to CSV.
    Nothing in this script writes to Active Directory, the registry, or any policy.
    Every command only reads.

    Checks covered: protocol state (LM / NTLM / LDAP / SMB), Kerberos (KRBTGT age,
    duplicate SPNs, RC4, pre-auth), delegation (unconstrained, constrained, RBCD,
    protocol transition), privileged groups, LAPS coverage, stale objects,
    GPO hygiene, SYSVOL/replication state, security log sizing.

.PARAMETER OutputFolder
    Where to write the CSV files. Defaults to a timestamped folder under Documents.

.PARAMETER StaleDays
    Age in days after which a computer or user account counts as stale. Default 120.

.EXAMPLE
    .\AD-Collect.ps1

.EXAMPLE
    .\AD-Collect.ps1 -OutputFolder C:\Temp\ad-collect -StaleDays 90

.NOTES
    Requires: the ActiveDirectory PowerShell module, and WinRM or remote registry
    access to every domain controller for the registry and SMB checks.
    Run as a Domain Admin or equivalent; delegated roles will fail on the DC checks
    and succeed on the AD queries.
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = (Join-Path ([Environment]::GetFolderPath('MyDocuments')) ("ad-collect-" + (Get-Date -Format 'yyyyMMdd-HHmm'))),
    [int]$StaleDays = 120
)

$ErrorActionPreference = 'Continue'
$results = [ordered]@{}
$failures = @()

function Save-Result {
    param([string]$Name, $Data)
    $path = Join-Path $OutputFolder ("{0}.csv" -f $Name)
    if ($null -eq $Data -or ($Data -is [array] -and $Data.Count -eq 0)) {
        "" | Set-Content -Path $path -Encoding UTF8
        Write-Host ("  [empty] {0}" -f $Name) -ForegroundColor DarkGray
        return
    }
    $Data | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    Write-Host ("  [ok]    {0}" -f $Name) -ForegroundColor Green
}

function Invoke-Check {
    param([string]$Name, [scriptblock]$Body)
    Write-Host ("== {0}" -f $Name) -ForegroundColor Cyan
    try {
        $data = & $Body
        Save-Result -Name $Name -Data $data
    } catch {
        $failures += [pscustomobject]@{ Check = $Name; Error = $_.Exception.Message }
        Write-Host ("  [fail]  {0}: {1}" -f $Name, $_.Exception.Message) -ForegroundColor Yellow
    }
}

if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
Write-Host ("Output: {0}" -f $OutputFolder) -ForegroundColor White

Import-Module ActiveDirectory -ErrorAction Stop

$dcs    = @((Get-ADDomainController -Filter *).Name)
$domain = Get-ADDomain
$cutoff = (Get-Date).AddDays(-$StaleDays)

Write-Host ("`nDomain: {0} | DCs: {1} | Stale threshold: {2} days`n" -f $domain.DNSRoot, $dcs.Count, $StaleDays)

# ---------------------------------------------------------------- A. protocols

Invoke-Check 'A1-LmCompatibilityLevel' {
    Invoke-Command -ComputerName $dcs -ErrorAction Stop -ScriptBlock {
        [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            LmCompatibilityLevel = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
        }
    }
}

Invoke-Check 'A2-SmbSigning' {
    Invoke-Command -ComputerName $dcs -ErrorAction Stop -ScriptBlock {
        $c = Get-SmbServerConfiguration
        [pscustomobject]@{
            ComputerName            = $env:COMPUTERNAME
            RequireSecuritySignature = $c.RequireSecuritySignature
            EnableSecuritySignature  = $c.EnableSecuritySignature
        }
    }
}

Invoke-Check 'A3-LdapSigning-ChannelBinding' {
    Invoke-Command -ComputerName $dcs -ErrorAction Stop -ScriptBlock {
        [pscustomobject]@{
            ComputerName            = $env:COMPUTERNAME
            LDAPServerIntegrity     = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerIntegrity -ErrorAction SilentlyContinue).LDAPServerIntegrity
            LdapEnforceChannelBinding = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Lsa' -Name LdapEnforceChannelBinding -ErrorAction SilentlyContinue).LdapEnforceChannelBinding
            RestrictAnonymous       = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -ErrorAction SilentlyContinue).RestrictAnonymous
        }
    }
}

Invoke-Check 'A5-NtlmRestrictions' {
    Invoke-Command -ComputerName $dcs -ErrorAction Stop -ScriptBlock {
        $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
        [pscustomobject]@{
            ComputerName              = $env:COMPUTERNAME
            RestrictSendingNTLMTraffic = (Get-ItemProperty $p -Name RestrictSendingNTLMTraffic -ErrorAction SilentlyContinue).RestrictSendingNTLMTraffic
            RestrictReceivingNTLMTraffic = (Get-ItemProperty $p -Name RestrictReceivingNTLMTraffic -ErrorAction SilentlyContinue).RestrictReceivingNTLMTraffic
            AuditNTLMInDomain         = (Get-ItemProperty $p -Name AuditNTLMInDomain -ErrorAction SilentlyContinue).AuditNTLMInDomain
        }
    }
}

# ---------------------------------------------------------------- B. kerberos

Invoke-Check 'B1-Krbtgt' {
    Get-ADUser krbtgt -Properties PasswordLastSet, msDS-KeyVersionNumber |
        Select-Object Name, PasswordLastSet, msDS-KeyVersionNumber, Enabled
}

Invoke-Check 'B2-DuplicateSpn' {
    $raw = & setspn -X 2>&1
    $raw | Where-Object { $_ -match '\S' } | ForEach-Object { [pscustomobject]@{ Output = $_ } }
}

Invoke-Check 'B3-Rc4SupportedEtypes' {
    Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes>=0)' -Properties msDS-SupportedEncryptionTypes |
        Where-Object { $_.'msDS-SupportedEncryptionTypes' -band 4 } |
        Select-Object Name, ObjectClass, msDS-SupportedEncryptionTypes
}

Invoke-Check 'B4-PreAuthDisabled' {
    Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth |
        Select-Object Name, Enabled, PasswordLastSet, DistinguishedName
}

# ---------------------------------------------------------------- C. delegation

Invoke-Check 'C1-UnconstrainedDelegation' {
    $unc = Get-ADObject -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties SamAccountName, ObjectClass
    $unc | Where-Object { $dcs -notcontains ($_.Name -replace '\$$', '') } |
        Select-Object Name, ObjectClass, DistinguishedName
}

Invoke-Check 'C2-ConstrainedDelegation' {
    Get-ADObject -Filter * -Properties msDS-AllowedToDelegateTo |
        Where-Object { $_.'msDS-AllowedToDelegateTo' } |
        Select-Object Name, @{ n = 'Targets'; e = { $_.'msDS-AllowedToDelegateTo' -join '; ' } }
}

Invoke-Check 'C3-Rbcd' {
    Get-ADObject -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
        Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } |
        Select-Object Name, ObjectClass, DistinguishedName
}

Invoke-Check 'C4-ProtocolTransition' {
    Get-ADObject -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=16777216)' -Properties SamAccountName, ObjectClass |
        Select-Object Name, ObjectClass, DistinguishedName
}

# ------------------------------------------------------- D. privileged access

Invoke-Check 'D1-DomainAdmins-Effective' {
    $direct = @((Get-ADGroupMember 'Domain Admins').SamAccountName)
    $all    = @((Get-ADGroupMember 'Domain Admins' -Recursive).SamAccountName)
    $all | ForEach-Object {
        [pscustomobject]@{
            SamAccountName = $_
            DirectMember   = ($direct -contains $_)
        }
    }
}

Invoke-Check 'D3-Tier0Groups' {
    'Enterprise Admins', 'Schema Admins', 'Account Operators', 'Backup Operators', 'Server Operators', 'Group Policy Creator Owners' |
        ForEach-Object {
            $g = $_
            try {
                Get-ADGroupMember $g -Recursive -ErrorAction Stop |
                    Select-Object @{ n = 'Group'; e = { $g } }, Name, SamAccountName, objectClass
            } catch {
                [pscustomobject]@{ Group = $g; Name = "ERR: $($_.Exception.Message)"; SamAccountName = ''; objectClass = '' }
            }
        }
}

Invoke-Check 'D4-ProtectedUsers' {
    Get-ADGroupMember 'Protected Users' -Recursive -ErrorAction SilentlyContinue |
        Select-Object Name, SamAccountName, objectClass
}

Invoke-Check 'D5-LapsCoverage' {
    Get-ADComputer -Filter * -Properties 'msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime', Enabled, OperatingSystem |
        Where-Object { -not $_.'msLAPS-PasswordExpirationTime' -and -not $_.'ms-Mcs-AdmPwdExpirationTime' } |
        Select-Object Name, Enabled, OperatingSystem |
        Sort-Object Enabled -Descending
}

Invoke-Check 'D6-AdminCountObjects' {
    Get-ADObject -Filter 'AdminCount -eq 1' -Properties AdminCount |
        Select-Object Name, ObjectClass, DistinguishedName
}

# --------------------------------------------------------------- E. accounts

Invoke-Check 'E1-StaleComputers' {
    Get-ADComputer -Filter * -Properties LastLogonDate, Enabled, OperatingSystem |
        Where-Object { $_.Enabled -eq $true -and $_.LastLogonDate -ne $null -and $_.LastLogonDate -lt $cutoff } |
        Select-Object Name, LastLogonDate, OperatingSystem |
        Sort-Object LastLogonDate
}

Invoke-Check 'E2-StaleUsers' {
    Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate, PasswordLastSet |
        Where-Object { $_.LastLogonDate -ne $null -and $_.LastLogonDate -lt $cutoff } |
        Select-Object Name, LastLogonDate, PasswordLastSet |
        Sort-Object LastLogonDate
}

Invoke-Check 'E3-UsersWithSpn' {
    Get-ADUser -Filter { ServicePrincipalName -ne "$null" } -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires |
        Select-Object Name, PasswordLastSet, PasswordNeverExpires,
            @{ n = 'SPNs'; e = { $_.ServicePrincipalName -join '; ' } }
}

Invoke-Check 'E4-PasswordNeverExpires' {
    Get-ADUser -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $true } -Properties PasswordLastSet |
        Select-Object Name, PasswordLastSet |
        Sort-Object PasswordLastSet
}

Invoke-Check 'E5-MachineAccountQuota' {
    [pscustomobject]@{
        Domain              = $domain.DNSRoot
        MachineAccountQuota = $domain.MachineAccountQuota
        DomainMode          = $domain.DomainMode
        ForestMode          = (Get-ADForest).ForestMode
    }
}

# ------------------------------------------------------------------- F. GPO/repl

Invoke-Check 'F1-UnlinkedGpos' {
    Get-GPO -All | Where-Object {
        $_.GpoStatus -ne 'AllSettingsDisabled' -and
        -not ((Get-GPOReport -Guid $_.Id -ReportType Xml) -match '<LinksTo>')
    } | Select-Object DisplayName, ModificationTime, GpoStatus
}

Invoke-Check 'F2-EmptyGpos' {
    Get-GPO -All | Where-Object { $_.Computer.DSVersion -eq 0 -and $_.User.DSVersion -eq 0 } |
        Select-Object DisplayName, CreationTime, ModificationTime
}

Invoke-Check 'F4-SysvolState' {
    $d = & dfsrmig /getglobalstate 2>&1
    $d | Where-Object { $_ -match '\S' } | ForEach-Object { [pscustomobject]@{ Output = $_ } }
}

Invoke-Check 'F5-ReplicationFailures' {
    & repadmin /showrepl * /csv 2>&1 | ConvertFrom-Csv |
        Where-Object { $_.'Number of Failures' -and [int]$_.'Number of Failures' -gt 0 } |
        Select-Object 'Destination DSA', 'Source DSA', 'Naming Context', 'Number of Failures', 'Last Failure Time'
}

# ----------------------------------------------------------------- H. logging

Invoke-Check 'H3-SecurityLogSize' {
    Invoke-Command -ComputerName $dcs -ErrorAction Stop -ScriptBlock {
        Get-WinEvent -ListLog Security |
            Select-Object @{ n = 'ComputerName'; e = { $env:COMPUTERNAME } }, LogName, MaximumSizeInBytes, RecordCount, LogMode
    }
}

# ------------------------------------------------------------------ summary

Write-Host ("`nDone. Files: {0}" -f $OutputFolder) -ForegroundColor White
Get-ChildItem $OutputFolder -Filter *.csv | Select-Object Name, Length | Format-Table -AutoSize

if ($failures.Count -gt 0) {
    Write-Host "`nChecks that could not complete:" -ForegroundColor Yellow
    $failures | ForEach-Object { Write-Host ("  {0}: {1}" -f $_.Check, $_.Error) -ForegroundColor Yellow }
    $failures | Export-Csv -Path (Join-Path $OutputFolder '_failures.csv') -NoTypeInformation -Encoding UTF8
}

Write-Host "`nReminder: nothing in this script changes a setting. Read the output before you change anything." -ForegroundColor DarkGray
