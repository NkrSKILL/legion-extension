# Сборка Legion-Setup.exe
#
#   powershell -ExecutionPolicy Bypass -File installer\build.ps1
#
# Что происходит:
#   1. Отдельное venv (installer\build\venv) с зависимостями сервера + PyInstaller
#   2. legion-server.exe  — локальный FastAPI-сервер (backend\server_main.py)
#   3. legion-host.exe    — нативный хост Chrome (installer\native-host\legion_host.py)
#   4. Раскладка файлов в installer\build\stage (без .env, ключей и тестов)
#   5. Inno Setup компилирует installer\output\Legion-Setup.exe
#
# Требования: Python 3.10+ в PATH, Inno Setup 6 (ISCC.exe), ключ keys\legion-extension.pem
# (создаётся один раз: python installer\tools\extension_key.py make).

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Build = Join-Path $Root 'installer\build'
$Stage = Join-Path $Build 'stage'
$Dist = Join-Path $Build 'dist'
$Work = Join-Path $Build 'work'
$Spec = Join-Path $Build 'spec'
$Venv = Join-Path $Build 'venv'
$Out = Join-Path $Root 'installer\output'
$Iss = Join-Path $Root 'installer\legion.iss'
$Icon = Join-Path $Root 'installer\assets\legion.ico'
$Py = Join-Path $Venv 'Scripts\python.exe'

function Write-Step([string]$Message) {
    Write-Host ''
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Команда завершилась с кодом ${LASTEXITCODE}: $File $($Arguments -join ' ')"
    }
}

function Find-Iscc {
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
        'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
        'C:\Program Files\Inno Setup 6\ISCC.exe'
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    throw 'Inno Setup 6 не найден. Установите: winget install JRSoftware.InnoSetup'
}

# ---------------------------------------------------------------- 0. проверки
Write-Step 'Проверка исходников'
$manifest = Get-Content (Join-Path $Root 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$Version = [string]$manifest.version
if (-not $manifest.key) { throw 'В manifest.json нет поля key. Выполните: python installer\tools\extension_key.py make' }
if (-not (Test-Path $Icon)) { throw "Нет иконки $Icon. Запустите: python installer\tools\make_brand.py" }
if (-not (Test-Path (Join-Path $Root 'keys\legion-extension.pem'))) {
    throw 'Нет keys\legion-extension.pem. Без него ID расширения изменится. Восстановите ключ из резервной копии.'
}

# Ключ и .env не должны попасть в установщик — проверим в конце
# BOM у .iss нужен, чтобы Inno корректно прочитал русские строки
$issBytes = [IO.File]::ReadAllBytes($Iss)
if (-not ($issBytes.Length -ge 3 -and $issBytes[0] -eq 0xEF -and $issBytes[1] -eq 0xBB -and $issBytes[2] -eq 0xBF)) {
    [IO.File]::WriteAllBytes($Iss, [byte[]](0xEF, 0xBB, 0xBF) + $issBytes)
}

$ExtId = (& python (Join-Path $Root 'installer\tools\extension_key.py') id).Trim()
if ($ExtId -notmatch '^[a-p]{32}$') { throw "Некорректный ID расширения: '$ExtId'" }
Write-Host "Версия: $Version   ID расширения: $ExtId"

# ---------------------------------------------------------------- 1. venv
Write-Step 'Окружение сборки'
if (-not (Test-Path $Py)) {
    Invoke-Checked 'python' @('-m', 'venv', $Venv)
}
Invoke-Checked $Py @('-m', 'pip', 'install', '--disable-pip-version-check', '--quiet',
    'fastapi>=0.115.0', 'uvicorn>=0.32.0', 'pydantic>=2.0.0', 'python-dotenv>=1.0.0', 'httpx>=0.27.0',
    'pyinstaller>=6.0', 'cryptography>=42.0')

# ---------------------------------------------------------------- 2. сборка exe
Write-Step 'Сборка legion-server.exe'
Invoke-Checked $Py @('-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir', '--noconsole',
    '--name', 'legion-server',
    '--icon', $Icon,
    '--paths', (Join-Path $Root 'backend'),
    '--collect-submodules', 'uvicorn',
    '--collect-submodules', 'app',
    '--distpath', $Dist, '--workpath', $Work, '--specpath', $Spec,
    (Join-Path $Root 'backend\server_main.py'))

Write-Step 'Сборка legion-host.exe'
Invoke-Checked $Py @('-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir', '--noconsole',
    '--name', 'legion-host',
    '--icon', $Icon,
    '--distpath', $Dist, '--workpath', $Work, '--specpath', $Spec,
    (Join-Path $Root 'installer\native-host\legion_host.py'))

# ---------------------------------------------------------------- 3. раскладка
Write-Step 'Раскладка файлов (stage)'
if (Test-Path $Stage) { Remove-Item $Stage -Recurse -Force }
New-Item -ItemType Directory -Path $Stage | Out-Null

Copy-Item (Join-Path $Dist 'legion-server') (Join-Path $Stage 'server') -Recurse
Copy-Item (Join-Path $Dist 'legion-host') (Join-Path $Stage 'host') -Recurse

# Сервер пишет threat_feeds.json / stats.json рядом с собой; brands.json читается отсюда
$serverData = Join-Path $Stage 'server\data'
New-Item -ItemType Directory -Path $serverData -Force | Out-Null
Copy-Item (Join-Path $Root 'data\brands.json') (Join-Path $serverData 'brands.json')

# Расширение — только то, что реально нужно Chrome
$ext = Join-Path $Stage 'extension'
New-Item -ItemType Directory -Path $ext | Out-Null
Copy-Item (Join-Path $Root 'manifest.json') $ext
foreach ($dir in 'background', 'content', 'popup', 'options', 'icons', 'data') {
    Copy-Item (Join-Path $Root $dir) (Join-Path $ext $dir) -Recurse
}

# Проверка: в установщике не должно быть секретов и служебных файлов
$forbidden = Get-ChildItem $Stage -Recurse -Force |
    Where-Object { $_.Name -match '^\.env' -or $_.Extension -in '.pem', '.key' -or $_.Name -match '^test_|^run_checks' }
if ($forbidden) {
    $forbidden | ForEach-Object { Write-Host "  запрещённый файл: $($_.FullName)" -ForegroundColor Red }
    throw 'В stage попали секреты или служебные файлы'
}
$fileCount = (Get-ChildItem $Stage -Recurse -File).Count
Write-Host "Файлов в stage: $fileCount"

# ---------------------------------------------------------------- 4. установщик
Write-Step 'Сборка Legion-Setup.exe (Inno Setup)'
$Iscc = Find-Iscc
New-Item -ItemType Directory -Path $Out -Force | Out-Null
$SetupExe = Join-Path $Out 'Legion-Setup.exe'
if (Test-Path $SetupExe) { Remove-Item $SetupExe -Force }

Invoke-Checked $Iscc @(
    '/Qp',
    "/DAppVersion=$Version",
    "/DStageDir=$Stage",
    "/DExtensionId=$ExtId",
    "/DOutputDir=$Out",
    $Iss
)

if (-not (Test-Path $SetupExe)) { throw 'Установщик не создан' }
$hash = (Get-FileHash $SetupExe -Algorithm SHA256).Hash
$sizeMb = [math]::Round((Get-Item $SetupExe).Length / 1MB, 1)
Write-Host ''
Write-Host "Готово: $SetupExe ($sizeMb МБ)" -ForegroundColor Green
Write-Host "SHA256: $hash"
