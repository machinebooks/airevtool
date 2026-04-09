param(
    [switch]$SkipDeploy
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$solutionPath = Join-Path $repoRoot 'x64dbg-plugin/build/AIrevPlugin.sln'
$pluginOutput = Join-Path $repoRoot 'x64dbg-plugin/build/Release/AIrevPlugin.dp64'
$deployPath = Join-Path $repoRoot '../x64dbg/bin/plugins/AIrevPlugin.dp64'

if (-not (Test-Path $solutionPath)) {
    throw "No se encontro la solucion del plugin: $solutionPath"
}

$candidateMsbuildPaths = @(
    'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe',
    'C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe',
    'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe',
    'C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe',
    'C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe',
    'C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe'
)

$msbuild = $candidateMsbuildPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $msbuild) {
    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $installationPath = & $vswhere -latest -requires Microsoft.Component.MSBuild -property installationPath | Select-Object -First 1
        if ($installationPath) {
            $resolved = Join-Path $installationPath 'MSBuild\Current\Bin\MSBuild.exe'
            if (Test-Path $resolved) {
                $msbuild = $resolved
            }
        }
    }
}

if (-not $msbuild) {
    throw 'No se encontro MSBuild. Instala Visual Studio Build Tools o Visual Studio con MSBuild.'
}

Write-Host "Compilando AIrevPlugin con $msbuild"
& $msbuild $solutionPath /p:Configuration=Release /p:Platform=x64 /m

if ($LASTEXITCODE -ne 0) {
    throw "MSBuild fallo con codigo $LASTEXITCODE"
}

if (-not (Test-Path $pluginOutput)) {
    throw "No se genero el plugin esperado: $pluginOutput"
}

if ($SkipDeploy) {
    Write-Host "Plugin compilado en $pluginOutput"
    exit 0
}

$deployDir = Split-Path -Parent $deployPath
if (-not (Test-Path $deployDir)) {
    throw "No se encontro el directorio de plugins de x64dbg: $deployDir"
}

Copy-Item $pluginOutput $deployPath -Force
Write-Host "Plugin desplegado en $deployPath"