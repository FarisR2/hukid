# Portable test tooling only. No service, PATH mutation, or existing database.
$ErrorActionPreference = 'Stop'
$workspaceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$toolDirectory = Join-Path $workspaceRoot '.cache/toolchains'
$archivePath = Join-Path $toolDirectory 'postgresql-18.6-5-windows-x64-binaries.zip'
$extractDirectory = Join-Path $toolDirectory 'postgresql-18.6-5'
$postgresPath = Join-Path $extractDirectory 'pgsql/bin/postgres.exe'
New-Item -ItemType Directory -Force -Path $toolDirectory | Out-Null
if (!(Test-Path -LiteralPath $archivePath)) {
 Invoke-WebRequest -Uri 'https://get.enterprisedb.com/postgresql/postgresql-18.6-5-windows-x64-binaries.zip' -OutFile $archivePath
}
if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'e2246ba91d22345bc3d017586c09ede52d9df180b1eeb480f050445f1cad84e2') {
 throw 'PostgreSQL archive checksum mismatch; no extraction performed'
}
if (!(Test-Path -LiteralPath $postgresPath)) {
 Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDirectory
}
$version = & $postgresPath --version
if ($LASTEXITCODE -ne 0 -or $version -notmatch '\b18\.6\b') { throw 'Expected PostgreSQL 18.6' }
Write-Output 'Verified PostgreSQL 18.6 portable test tooling'
