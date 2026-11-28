param([switch]$Package, [string]$BinaryDirectory, [string]$PackageDirectory)

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
    if (!$BinaryDirectory) { $BinaryDirectory = $project }
    New-Item -ItemType Directory -Path $BinaryDirectory -Force | Out-Null
    $exe = Join-Path $BinaryDirectory 'GuestGate.exe'
    $dll = Join-Path $BinaryDirectory 'GuestGateRecorder.dll'
    & cargo +1.88.0-x86_64-pc-windows-msvc build --release --locked --manifest-path native/recorder/Cargo.toml
    if ($LASTEXITCODE -ne 0) { throw "Recorder build failed ($LASTEXITCODE)" }
    Copy-Item -LiteralPath native/recorder/target/release/guestgate_recorder.dll -Destination $dll -Force
    & go build -tags production -ldflags '-H windowsgui' -o $exe .
    if ($LASTEXITCODE -ne 0) { throw "go build exited with code $LASTEXITCODE" }
    if ($Package) {
        $version = (Get-Item -LiteralPath $exe).VersionInfo.ProductVersion
        if (!$PackageDirectory) { $PackageDirectory = Join-Path $project "dist" }
        $output = Join-Path $PackageDirectory "GuestGate-v$version-windows-amd64"
        $scriptPath = 'integrations/clash-node-ports.js'
        New-Item -ItemType Directory -Force -Path (Join-Path $output (Split-Path $scriptPath)) | Out-Null
        Copy-Item -LiteralPath $exe,$dll,'wechat-qr.svg' -Destination $output
        Copy-Item -LiteralPath $scriptPath -Destination (Join-Path $output $scriptPath)
        $readme = [IO.File]::ReadAllText((Join-Path $project 'README.md'))
        $readme = [regex]::Replace($readme, '(?m)^!\[[^\]]*\]\(\./UI\.png\)\r?\n', '')
        [IO.File]::WriteAllText((Join-Path $output 'README.md'), $readme)
        $trust = '../ProxyLane/third_party/tls-trust'
        $thirdParty = [ordered]@{
            'ProxyLane' = '../ProxyLane/LICENSE'
            'TLS trust notices' = "$trust/NOTICE.txt"
            'webpki-root-certs' = "$trust/LICENSE-webpki-root-certs.txt"
            'rustls-platform-verifier' = "$trust/LICENSE-rustls-platform-verifier.txt"
            'h3-quinn' = '../ProxyLane/third_party/h3-quinn/LICENSE'
        }
        $separator = '=' * 72
        $licenseParts = @(
            [IO.File]::ReadAllText((Join-Path $project 'LICENSE'))
            "$separator`r`nThird-Party Software Licenses`r`n$separator"
            foreach ($entry in $thirdParty.GetEnumerator()) {
                "$($entry.Key) ($([IO.Path]::GetFileName($entry.Value)))`r`n$separator"
                [IO.File]::ReadAllText((Join-Path $project $entry.Value))
            }
        )
        [IO.File]::WriteAllText((Join-Path $output 'LICENSE'), ($licenseParts -join "`r`n`r`n"))
        # Use explicit archive entries so old staging directories cannot add obsolete files.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archivePath = Join-Path $PackageDirectory ([IO.Path]::GetRandomFileName())
        try {
            $archive = [IO.Compression.ZipFile]::Open($archivePath, [IO.Compression.ZipArchiveMode]::Create)
            try {
                foreach ($entry in @('GuestGate.exe','GuestGateRecorder.dll','LICENSE','wechat-qr.svg','README.md',$scriptPath)) {
                    [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, (Join-Path $output $entry), $entry)
                }
            } finally {
                $archive.Dispose()
            }
            Move-Item -LiteralPath $archivePath -Destination "$output.zip" -Force
        } finally {
            if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath }
        }
    }
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
    $env:GOOS = $previousOS
    $env:GOARCH = $previousArch
    Pop-Location
}
