@echo off
setlocal

set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_EXE%" set "PS_EXE=powershell"

set "PS_CMD=$ErrorActionPreference='Stop';$downloads=[Environment]::GetFolderPath('UserProfile') + '\Downloads';$stamp=Get-Date -Format 'yyyyMMdd-HHmmss';$outputPath=Join-Path $downloads ('ids-pc-activity-' + $stamp + '.csv');$sampleTime=(Get-Date).ToString('o');$tcpRows=Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object @{Name='sample_time';Expression={$sampleTime}},@{Name='protocol';Expression={'tcp'}},@{Name='local_address';Expression={$_.LocalAddress}},@{Name='local_port';Expression={$_.LocalPort}},@{Name='remote_address';Expression={$_.RemoteAddress}},@{Name='remote_port';Expression={$_.RemotePort}},@{Name='state';Expression={$_.State}},@{Name='owning_process';Expression={$_.OwningProcess}};$udpRows=Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object @{Name='sample_time';Expression={$sampleTime}},@{Name='protocol';Expression={'udp'}},@{Name='local_address';Expression={$_.LocalAddress}},@{Name='local_port';Expression={$_.LocalPort}},@{Name='remote_address';Expression={''}},@{Name='remote_port';Expression={0}},@{Name='state';Expression={'LISTEN'}},@{Name='owning_process';Expression={$_.OwningProcess}};$rows=@($tcpRows)+@($udpRows);if($rows.Count -eq 0){ throw 'No network activity rows found. Try running as Administrator.' };$rows | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8;Write-Host '';Write-Host 'CSV exported successfully:' -ForegroundColor Green;Write-Host $outputPath;Write-Host '';Write-Host 'Upload this file in dashboard -> CSV Batch Analysis -> Analyze CSV';"
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -Command "%PS_CMD%"

if errorlevel 1 (
  echo.
  echo Export failed.
) else (
  echo.
  echo Export completed.
)

pause
