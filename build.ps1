param(
    [string]$GoPath,
    [string]$Output = 'dist\vps-speedtest.exe',
    [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
$savedEnv = @{}
foreach ($key in @('GOOS','GOARCH','GOCACHE','GOENV','GOTOOLCHAIN','CGO_ENABLED')) {
    $savedEnv[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
}
try {
    if (-not $GoPath) {
        if (Test-Path -LiteralPath '.tools\go\bin\go.exe') { $GoPath = Join-Path $PSScriptRoot '.tools\go\bin\go.exe' }
        else { $GoPath = (Get-Command go -ErrorAction Stop).Source }
    }
    $GoPath = (Resolve-Path -LiteralPath $GoPath).Path
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    $env:GOENV = 'off'
    $env:GOTOOLCHAIN = 'local'
    $env:GOCACHE = Join-Path $PSScriptRoot '.tools\gocache'
    if (-not $SkipTests) {
        & $GoPath test -count=1 main.go main_test.go
        if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
        & $GoPath vet main.go main_test.go
        if ($LASTEXITCODE -ne 0) { throw 'Go vet failed.' }
    }
    $outputPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $Output))
    if ($outputPath -eq (Join-Path $PSScriptRoot 'vps-speedtest.exe')) { throw 'Build into dist first; preserve and verify the current executable before replacing it.' }
    New-Item -ItemType Directory -Path (Split-Path -Parent $outputPath) -Force | Out-Null
    & $GoPath build -trimpath -ldflags '-H=windowsgui -s -w' -o $outputPath main.go
    if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    Write-Host "Built: $outputPath"
    Get-FileHash -LiteralPath $outputPath -Algorithm SHA256
}
finally {
    foreach ($key in $savedEnv.Keys) { [Environment]::SetEnvironmentVariable($key, $savedEnv[$key], 'Process') }
    Pop-Location
}
