param(
  [string]$Output = "autopsy-phishing-detection-plugin.zip"
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
Set-Location $root

$items = @(
  'phishing_detector_main.py',
  'phishing_detector',
  'README.md', 'LICENSE', 'CHANGELOG.md'
)

if (Test-Path $Output) { Remove-Item $Output -Force }
Compress-Archive -Path $items -DestinationPath $Output -Force
Write-Host "Created package: $Output"
