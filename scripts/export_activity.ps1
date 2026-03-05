param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $downloads = [Environment]::GetFolderPath("UserProfile") + "\Downloads"
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputPath = Join-Path $downloads "ids-pc-activity-$stamp.csv"
}

$sampleTime = (Get-Date).ToString("o")

$tcpRows = Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object `
    @{Name="sample_time";Expression={$sampleTime}},
    @{Name="protocol";Expression={"tcp"}},
    @{Name="local_address";Expression={$_.LocalAddress}},
    @{Name="local_port";Expression={$_.LocalPort}},
    @{Name="remote_address";Expression={$_.RemoteAddress}},
    @{Name="remote_port";Expression={$_.RemotePort}},
    @{Name="state";Expression={$_.State}},
    @{Name="owning_process";Expression={$_.OwningProcess}}

$udpRows = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object `
    @{Name="sample_time";Expression={$sampleTime}},
    @{Name="protocol";Expression={"udp"}},
    @{Name="local_address";Expression={$_.LocalAddress}},
    @{Name="local_port";Expression={$_.LocalPort}},
    @{Name="remote_address";Expression={""}},
    @{Name="remote_port";Expression={0}},
    @{Name="state";Expression={"LISTEN"}},
    @{Name="owning_process";Expression={$_.OwningProcess}}

$rows = @($tcpRows) + @($udpRows)

if ($rows.Count -eq 0) {
    Write-Error "No network activity rows found. Try running PowerShell as Administrator."
}

$directory = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($directory) -and -not (Test-Path $directory)) {
    New-Item -Path $directory -ItemType Directory -Force | Out-Null
}

$rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "CSV exported successfully:" -ForegroundColor Green
Write-Host $OutputPath
Write-Host ""
Write-Host "Upload this file in dashboard -> CSV Batch Analysis -> Analyze CSV"
