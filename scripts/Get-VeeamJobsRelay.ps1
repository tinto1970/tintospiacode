#Requires -Version 7.0
<#
.SYNOPSIS
    Collects all Veeam backup jobs and outputs JSON to stdout.

.DESCRIPTION
    Loads the Veeam PowerShell module, connects to a Veeam B&R server,
    collects all jobs via Get-VBRJob (which includes all job types: Backup,
    EpAgentBackup, VmbApiPolicyTempJob/ProxmoxVE, etc.), and writes
    the result as JSON to stdout.

    Designed to be run on a Linux relay host (rocky01.station) via SSH
    from tintospia. The caller reads stdout as the JSON payload.

.PARAMETER ModulePath
    Full path to Veeam.Backup.PowerShell.psd1.

.PARAMETER Server
    Veeam B&R server hostname or IP.

.PARAMETER Username
    Veeam B&R username (local or domain).

.PARAMETER Password
    Veeam B&R password (plain text — passed via stdin or env from tintospia).

.EXAMPLE
    pwsh -NonInteractive -File Get-VeeamJobsRelay.ps1 \
         -ModulePath /opt/veeam/powershell/Veeam.Backup.PowerShell/Veeam.Backup.PowerShell.psd1 \
         -Server win2022-2.station -Username tintospia -Password 'Password1!'
#>
param(
    [string]$ModulePath = "/opt/veeam/powershell/Veeam.Backup.PowerShell/Veeam.Backup.PowerShell.psd1",
    [string]$Server     = "",
    [string]$Username   = "",
    [string]$Password   = ""
)

$ErrorActionPreference = 'Stop'

# Suppress verbose/progress output that would pollute stdout JSON
$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'

# Load Veeam module
try {
    Import-Module $ModulePath -ErrorAction Stop 3>$null 4>$null 6>$null
} catch {
    Write-Error "Failed to load Veeam module from '$ModulePath': $_" 2>&1
    exit 1
}

# Connect to Veeam server
try {
    $secPass = ConvertTo-SecureString $Password -AsPlainText -Force
    $cred    = [System.Management.Automation.PSCredential]::new($Username, $secPass)
    Connect-VBRServer -Server $Server -Credential $cred -ErrorAction Stop 3>$null 4>$null 6>$null
} catch {
    Write-Error "Failed to connect to Veeam server '$Server': $_" 2>&1
    exit 2
}

$jobs = @(Get-VBRJob)
$output = foreach ($job in $jobs) {
    $session = $job.FindLastSession()
    [PSCustomObject]@{
        name             = $job.Name
        type             = $job.JobType.ToString()
        is_disabled      = [bool]$job.IsDisabled
        schedule_enabled = [bool]$job.IsScheduleEnabled
        last_result      = if ($session) { $session.Result.ToString()          } else { 'Never' }
        last_end_time    = if ($session) { $session.EndTime.ToString('o')       } else { ''      }
        last_state       = if ($session) { $session.State.ToString()           } else { ''      }
        last_start_time  = if ($session) { $session.CreationTime.ToString('o') } else { ''      }
    }
}

# Output JSON to stdout — this must be the only stdout output
$output | ConvertTo-Json -Depth 3 -AsArray

# Force-exit immediately before background Veeam threads (ClientTimeSyncProc etc.)
# crash with NullReferenceException on Linux — a known issue with the module.
[System.Environment]::Exit(0)
