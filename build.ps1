using namespace System.IO
using namespace System.Runtime.InteropServices

#Requires -Version 7.2

[CmdletBinding()]
param (
    [Parameter()]
    [string]
    $Configuration = 'Debug',

    [Parameter()]
    [Architecture[]]
    $Architecture = [RuntimeInformation]::OSArchitecture

    # Kerberos.NET does not seem to support this
    # [Parameter()]
    # [switch]
    # $PublishAot
)

$ErrorActionPreference = 'Stop'

$arguments = @(
    'publish'
    '--configuration', $Configuration
    '--verbosity', 'quiet'
    '-nologo'
    "-p:Version=1.0.0"
    # if ($PublishAot) {
    #     '-p:PublishAot=true'
    # }
)

$binPath = [Path]::Combine($PSScriptRoot, 'bin')
if (Test-Path -LiteralPath $binPath) {
    Remove-Item -LiteralPath $binPath -Recurse -Force
}
New-Item -Path $binPath -ItemType Directory | Out-Null

Get-ChildItem -LiteralPath $PSScriptRoot/src | ForEach-Object -Process {
    foreach ($arch in $Architecture) {
        $arch = $arch.ToString().ToLowerInvariant()
        Write-Host "Compiling $($_.Name) for $arch" -ForegroundColor Cyan

        $csproj = (Get-Item -Path "$([Path]::Combine($_.FullName, '*.csproj'))").FullName
        $outputDir = [Path]::Combine($binPath, $_.Name, $arch)
        New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
        dotnet @arguments --output $outputDir $csproj --runtime "win-$($arch.ToString().ToLowerInvariant())"

        if ($LASTEXITCODE) {
            throw "Failed to compiled code for $framework"
        }
    }
}
