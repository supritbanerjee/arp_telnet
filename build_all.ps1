# Build every target on Windows (MSYS2 / MinGW-w64 g++ on PATH).   Usage:  ./build_all.ps1 [-SkipTests]
param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$out  = Join-Path $root 'build'
New-Item -ItemType Directory -Force $out | Out-Null
$common = @('-std=c++17', '-O2', '-Wall', '-Wextra', '-Wno-missing-field-initializers', "-I$root/include", "-I$root/src", '-pthread')
$libs   = @('-static', '-lws2_32')

function Build($src, $exe, $extra) {
    Write-Host "  building $exe"
    & g++ @common $src -o (Join-Path $out $exe) @extra @libs
    if ($LASTEXITCODE -ne 0) { throw "build failed: $exe" }
}

Write-Host 'CLI tools'
foreach ($n in 'arp_lab', 'telnet_server', 'telnet_client', 'sniffer_cli') { Build "$root/src/${n}_main.cpp" "$n.exe" @() }
Write-Host 'Tests'
foreach ($i in 1..4) { Build "$root/src/phase${i}_test.cpp" "phase${i}_test.exe" @() }
Write-Host 'GUI'
Build "$root/src/mini_wireshark_main.cpp" 'mini_wireshark.exe' @('-mwindows', '-lcomctl32', '-lcomdlg32', '-lgdi32')

if (-not $SkipTests) {
    Write-Host 'Running tests'
    Push-Location $out
    foreach ($i in 1..4) { & ".\phase${i}_test.exe"; if ($LASTEXITCODE -ne 0) { Pop-Location; throw "phase$i tests failed" } }
    Pop-Location
}
Write-Host "Done -> $out"
