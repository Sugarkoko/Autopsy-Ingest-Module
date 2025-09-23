param(
  [string]$Target = "$env:APPDATA\autopsy\python_modules\autopsy-phishing-detection-plugin"
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
Write-Host "Installing to: $Target"
New-Item -ItemType Directory -Force -Path $Target | Out-Null
Copy-Item -Recurse -Force -Path (Join-Path $root '*') -Exclude @('.git', '.gitignore', '.gitattributes', 'dist', 'build') -Destination $Target
Write-Host "Install complete. Restart Autopsy to load the module."
