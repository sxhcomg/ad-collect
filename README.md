# AD-Collect

Read-only PowerShell collector for on-prem Active Directory.

It answers the questions I ask first when someone hands me an AD finding list: what protocols does this domain still accept, who can delegate to what, who is actually a Domain Admin, and which of these answers has nobody looked at since the last admin left.

**Nothing here writes.** No `Set-AD*`, no `New-ItemProperty`, no GPO edits. Every command reads a value and writes it to a CSV in the output folder.

## What it collects

| File | What it answers |
|---|---|
| `A1-LmCompatibilityLevel.csv` | Does the DC still accept NTLMv1? |
| `A2-SmbSigning.csv` | Is SMB signing required on the DCs? |
| `A3-LdapSigning-ChannelBinding.csv` | LDAP signing, channel binding, anonymous binds |
| `A5-NtlmRestrictions.csv` | NTLM audit and outbound restriction state |
| `B1-Krbtgt.csv` | KRBTGT password age and key version |
| `B2-DuplicateSpn.csv` | `setspn -X` output, forest wide |
| `B3-Rc4SupportedEtypes.csv` | Accounts still advertising RC4 |
| `B4-PreAuthDisabled.csv` | Accounts that skip pre-authentication |
| `C1-UnconstrainedDelegation.csv` | Unconstrained delegation, DCs excluded |
| `C2-ConstrainedDelegation.csv` | Constrained delegation targets |
| `C3-Rbcd.csv` | Resource-based constrained delegation |
| `C4-ProtocolTransition.csv` | Trusted-to-auth-for-delegation accounts |
| `D1-DomainAdmins-Effective.csv` | Recursive Domain Admins, flags direct membership |
| `D3-Tier0Groups.csv` | Enterprise/Schema/Account/Backup/Server Operators, GPO Creator Owners |
| `D4-ProtectedUsers.csv` | Protected Users membership |
| `D5-LapsCoverage.csv` | Computers with no LAPS password set |
| `D6-AdminCountObjects.csv` | Objects with `AdminCount=1` (leftover ACL protection) |
| `E1-StaleComputers.csv` | Enabled computers idle past the threshold |
| `E2-StaleUsers.csv` | Enabled users idle past the threshold |
| `E3-UsersWithSpn.csv` | User accounts with SPNs (service account sprawl) |
| `E4-PasswordNeverExpires.csv` | Enabled accounts with `PasswordNeverExpires` |
| `E5-MachineAccountQuota.csv` | MAQ, domain and forest functional level |
| `F1-UnlinkedGpos.csv` | GPOs linked to nothing |
| `F2-EmptyGpos.csv` | GPOs with no computer or user settings |
| `F4-SysvolState.csv` | `dfsrmig` global state |
| `F5-ReplicationFailures.csv` | Replication partners with failures |
| `H3-SecurityLogSize.csv` | Security log size and retention mode per DC |
| `_failures.csv` | Checks that could not complete, with the error |

## Usage

```powershell
# Default: %USERPROFILE%\Documents\ad-collect-<timestamp>
.\AD-Collect.ps1

# Explicit folder, 90-day stale threshold
.\AD-Collect.ps1 -OutputFolder C:\Temp\ad-collect -StaleDays 90
```

Requirements:

- The `ActiveDirectory` PowerShell module (RSAT or a domain controller).
- WinRM access to every DC for the registry, SMB and event-log checks. If WinRM is closed, run the A-series checks on each DC by hand — the CSV schema is one row per DC.
- Read-only AD rights are enough for the AD queries. The DC checks need local admin on the DC or a delegated role that can read those registry keys.

## Reading the output

The CSVs are raw answers, not a verdict. Two examples of why that matters:

- `C1-UnconstrainedDelegation.csv` returning rows is not automatically a finding. A jump server that is unconstrained and Tier-0 protected is a very different problem from a print server nobody owns.
- `E1-StaleComputers.csv` at 120 days will always have rows. The question is whether the machine is off or the owner left. Disable nothing until someone confirms.

## Not in scope

No exploitation, no AD CS ESC path testing, no BloodHound collection, no cloud/Entra policy. This is a configuration read.

## License

MIT. Run it, fork it, change the thresholds.

## Companion

There is a longer write-up of the fix order — which of these findings actually matter first, and what breaks when you change them — as a paid checklist: [On-Prem AD Hardening Checklist](https://tommusk1024.gumroad.com/l/ad-hardening-checklist)

The script is free and always will be. It tells you what your domain looks like. The checklist tells you what to do first and what will break when you do it.
