param(
    [string]$ManifestDirectory = (Join-Path $PSScriptRoot 'sample-manifests')
)
$ErrorActionPreference = 'Stop'
$env:PATH = (Join-Path $PSScriptRoot 'tools') + ';' + $env:PATH
Push-Location $PSScriptRoot
try {
    & (Join-Path $PSScriptRoot '.venv\Scripts\python.exe') main.py $ManifestDirectory
    if ($LASTEXITCODE -ne 0) { throw "SLIKUBE exited with code $LASTEXITCODE" }
} finally {
    Pop-Location
}
