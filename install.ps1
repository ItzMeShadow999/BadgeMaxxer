$Owner  = "ItzMeShadow999"
$Repo   = "badgemaxxer"
$Branch = "main"
$Base   = "https://raw.githubusercontent.com/$Owner/$Repo/$Branch"
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

function Install-BadgeMaxxer {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $ProgressPreference = "SilentlyContinue"

    Write-Host ""
    Write-Host "  BadgeMaxxer installer" -ForegroundColor Yellow
    Write-Host ""

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
            Move-Item -Force -Path $temp -Destination $target
        } catch {
            Remove-Item -Force -ErrorAction SilentlyContinue $temp
            Write-Bad "Could not fetch $file : $($_.Exception.Message)"
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
