#Requires -Version 7

<#
.SYNOPSIS
    Unified Zero Networks tooling module.

.DESCRIPTION
    Consolidates core Zero Networks helper functions into a single module with
    consistent naming, automatic banners, and shared API helpers.

.AUTHOR
    Olaf Gradin
#>

$privatePath = Join-Path $PSScriptRoot 'Private'
$publicPath  = Join-Path $PSScriptRoot 'Public'

if (Test-Path $privatePath) {
    Get-ChildItem -Path $privatePath -Filter '*.ps1' | Sort-Object Name | ForEach-Object {
        . $_.FullName
    }
}

if (Test-Path $publicPath) {
    Get-ChildItem -Path $publicPath -Filter '*.ps1' | Sort-Object Name | ForEach-Object {
        . $_.FullName
    }
}

Ensure-ZNWelcomeShown