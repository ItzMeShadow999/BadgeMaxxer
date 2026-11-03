$Owner  = "ItzMeShadow999"
$Repo   = "badgemaxxer"
$Tag    = $env:BADGEMAXXER_TAG
$Releases = "https://github.com/$Owner/$Repo/releases"
$Dir    = Join-Path $env:USERPROFILE "BadgeMaxxer"
$Files  = @("BadgeMaxxer.py", "Watcher/stream_watcher.py")
$Packages = @("websockets", "davey", "cryptography")

function Write-Step($text) { Write-Host "  $text" -ForegroundColor Yellow }
function Write-Ok($text)   { Write-Host "  $text" -ForegroundColor Green }
function Write-Bad($text)  { Write-Host "  $text" -ForegroundColor Red }

function Find-Python {
    foreach ($candidate in @(@("py", "-3"), @("python"), @("python3"))) {
        $exe = $candidate[0]
        $pre = @($candidate | Select-Object -Skip 1)
        if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
        try {
            $version = & $exe @pre --version 2>&1
            if ($LASTEXITCODE -eq 0 -and "$version" -match "Python 3") {
                return @{ Exe = $exe; Pre = $pre }
            }
        } catch { }
    }
    return $null
}

function Resolve-Tag {
    if ($Tag) { return $Tag }
    $api = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
    $release = Invoke-RestMethod -UseBasicParsing -Uri $api -Headers @{ "User-Agent" = "BadgeMaxxer-installer" }
    return $release.tag_name
}

function Install-BadgeMaxxer {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = "SilentlyContinue"

    Write-Host ""
    Write-Host "  BadgeMaxxer installer" -ForegroundColor Yellow
    Write-Host ""

    # Pin to a release tag and load its SHA256SUMS before anything is installed.
    $sumsTemp = Join-Path ([IO.Path]::GetTempPath()) ("BadgeMaxxer-SHA256SUMS-" + [Guid]::NewGuid().ToString("N"))
    $expected = @{}
    try {
        $Ref = Resolve-Tag
        if ($Ref -notmatch '^[A-Za-z0-9._-]+$') { throw "invalid release tag '$Ref'" }
        $Base = "https://raw.githubusercontent.com/$Owner/$Repo/$Ref"
        Write-Step "Release $Ref, fetching SHA256SUMS ..."
        Invoke-WebRequest -UseBasicParsing -Uri "$Releases/download/$Ref/SHA256SUMS" -OutFile $sumsTemp
        foreach ($line in Get-Content -Path $sumsTemp) {
            if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+?)\s*$') { $expected[$Matches[2]] = $Matches[1].ToLower() }
        }
        if ($expected.Count -eq 0) { throw "SHA256SUMS is empty or unreadable" }
    } catch {
        Write-Bad "Could not load release checksums, nothing was installed: $($_.Exception.Message)"
        return
    } finally {
        Remove-Item -Force -ErrorAction SilentlyContinue $sumsTemp
    }

    $py = Find-Python
    if (-not $py -and (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Step "Python 3 not found, installing it with winget ..."
        winget install -e --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements | Out-Null
        $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
        $py = Find-Python
    }
    if (-not $py) {
        Write-Bad "Python 3 is required. Install it from https://www.python.org/downloads/ (tick 'Add python.exe to PATH'), then run this again."
        return
    }

    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $Dir "Watcher") | Out-Null

    foreach ($file in $Files) {
        $target = Join-Path $Dir ($file -replace "/", "\")
        $temp = "$target.download"
        Write-Step "Fetching $file ...."
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$Base/$file" -OutFile $temp
            $actual = (Get-FileHash -Algorithm SHA256 -Path $temp).Hash.ToLower()
            if (-not $expected.ContainsKey($file)) { throw "no checksum listed for $file in SHA256SUMS" }
            if ($actual -ne $expected[$file]) { throw "checksum mismatch (expected $($expected[$file]), got $actual)" }
            Write-Ok "Verified $file (sha256 $($actual.Substring(0, 16))...)"
            Move-Item -Force -Path $temp -Destination $target
        } catch {
            Remove-Item -Force -ErrorAction SilentlyContinue $temp
            Write-Bad "Could not install $file : $($_.Exception.Message)"
            return
        }
    }
    Write-Ok "Files saved to $Dir (your session.json is never touched)"

    Write-Step "Installing Python packages: $($Packages -join ', ') ..."
    & $py.Exe @($py.Pre) -m pip install --quiet --disable-pip-version-check @Packages
    if ($LASTEXITCODE -ne 0) {
        Write-Bad "pip could not install every package, BadgeMaxxer will try again when it needs them."
    }

    Write-Ok "Starting BadgeMaxxer"
    Write-Host ""
    Set-Location $Dir
    & $py.Exe @($py.Pre) (Join-Path $Dir "BadgeMaxxer.py")
}

Install-BadgeMaxxer
