param([switch]$Package)

$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $PSScriptRoot
$resource = Join-Path $project 'assets/windows/guestgate_windows_amd64.syso'
$temporary = Join-Path (Split-Path -Parent $resource) ([IO.Path]::GetRandomFileName())
$previousOS = $env:GOOS
$previousArch = $env:GOARCH
Push-Location -LiteralPath $project
try {
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $preprocessor = @()
    if (Get-Command cat.exe -ErrorAction SilentlyContinue) {
        $preprocessor += '--preprocessor=cat'
    }
    & windres --target=pe-x86-64 @preprocessor -i assets/windows/guestgate.rc -o $temporary -O coff
    if ($LASTEXITCODE -ne 0) { throw "windres exited with code $LASTEXITCODE" }
    if ([IO.File]::Exists($resource)) {
        [IO.File]::Replace($temporary, $resource, [System.Management.Automation.Language.NullString]::Value)
    } else {
        [IO.File]::Move($temporary, $resource)
    }
    & go build -tags production -ldflags '-H windowsgui' -o GuestGate.exe .
    if ($LASTEXITCODE -ne 0) { throw "go build exited with code $LASTEXITCODE" }
    if ($Package) {
        $version = (Get-Item GuestGate.exe).VersionInfo.ProductVersion
        $output = Join-Path $project "dist/GuestGate-v$version-windows-amd64"
        $scriptPath = 'integrations/clash/node-ports.js'
        New-Item -ItemType Directory -Force -Path (Join-Path $output (Split-Path $scriptPath)) | Out-Null
        Copy-Item -LiteralPath 'GuestGate.exe','LICENSE','wechat-qr.svg' -Destination $output
        Copy-Item -LiteralPath $scriptPath -Destination (Join-Path $output $scriptPath)
        $readme = [IO.File]::ReadAllText((Join-Path $project 'README.md'))
        $readme = [regex]::Replace($readme, '(?m)^!\[[^\]]*\]\(\./UI\.png\)\r?\n', '')
        [IO.File]::WriteAllText((Join-Path $output 'README.md'), $readme)
        $files = @('GuestGate.exe','LICENSE','wechat-qr.svg','README.md','integrations') | ForEach-Object { Join-Path $output $_ }
        Compress-Archive -LiteralPath $files -DestinationPath "$output.zip" -Force
    }
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
    $env:GOOS = $previousOS
    $env:GOARCH = $previousArch
    Pop-Location
}
