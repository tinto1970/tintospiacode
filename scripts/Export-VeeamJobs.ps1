#Requires -Version 5.1
<#
.SYNOPSIS
    Exports all Veeam backup jobs (including ProxmoxVE) to a JSON file.

.DESCRIPTION
    Loads the Veeam PowerShell module, collects all jobs via Get-VBRJob
    (which includes job types not exposed by the VBR REST API, such as
    VmbApiPolicyTempJob / Proxmox VE jobs), and writes the result to a
    JSON file readable by tintospia.

    Schedule this script via Windows Task Scheduler on the Veeam server,
    matching the tintospia cron interval (e.g., every 10 minutes).

.PARAMETER OutputPath
    Path where the JSON file will be written.
    Default: C:\VeeamExport\jobs.json

.EXAMPLE
    .\Export-VeeamJobs.ps1
    .\Export-VeeamJobs.ps1 -OutputPath "\\fileserver\monitoring\veeam_jobs.json"

.NOTES
    Run as a user with at least Veeam Restore Operator role.
    The output directory must be writable by the task's run-as account.
#>
param(
    [string]$OutputPath = "C:\VeeamExport\jobs.json"
)

$ErrorActionPreference = 'Stop'

# Load Veeam PowerShell module
try {
    Import-Module 'Veeam.Backup.PowerShell' -ErrorAction SilentlyContinue
    if (-not (Get-Command Get-VBRJob -ErrorAction SilentlyContinue)) {
        Add-PSSnapin VeeamPSSnapIn
    }
} catch {
    Write-Error "Failed to load Veeam PowerShell module: $_"
    exit 1
}

# Collect all jobs with last session info
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

# Write JSON
$dir = Split-Path $OutputPath
if (-not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir | Out-Null
}

$output | ConvertTo-Json -Depth 3 -AsArray | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "$(Get-Date -Format 'o') Exported $($output.Count) jobs to $OutputPath"
