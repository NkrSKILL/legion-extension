# Legion — статистика вердиктов (для разработчиков)
# Запуск:  backend\stats.ps1
#          backend\stats.bat
# Сброс:   backend\stats.ps1 -Reset
# JSON:    backend\stats.ps1 -Raw
# Watch:   backend\stats.ps1 -Watch

param(
  [string]$BaseUrl = "http://127.0.0.1:8787",
  [switch]$Reset,
  [switch]$Raw,
  [switch]$Watch
)

$ErrorActionPreference = "Stop"
$base = $BaseUrl.TrimEnd("/")

function Get-LegionStats {
  try {
    return Invoke-RestMethod -Uri "$base/v1/stats" -Method Get -TimeoutSec 3
  } catch {
    Write-Host ""
    Write-Host "Backend недоступен: $base" -ForegroundColor Red
    Write-Host "Запусти backend\start.bat и повтори." -ForegroundColor Yellow
    Write-Host ""
    exit 1
  }
}

function Get-Pct([int]$n, [int]$t) {
  if ($t -le 0) { return "-" }
  return ("{0:N0}%" -f (100.0 * $n / $t))
}

function Show-Stats($s) {
  if ($Raw) {
    $s | ConvertTo-Json -Depth 6
    return
  }

  $total = [int]$s.total
  $safe = [int]$s.safe
  $caution = [int]$s.caution
  $danger = [int]$s.danger
  $continued = [int]$s.continued
  $hosts = [int]$s.unique_hosts
  $dupes = [int]$s.skipped_dupes

  Write-Host ""
  Write-Host "  Legion · статистика" -ForegroundColor Cyan
  Write-Host "  $base" -ForegroundColor DarkGray
  Write-Host ("  " + ("-" * 42)) -ForegroundColor DarkGray

  $rows = @(
    [pscustomobject]@{ Metric = "Всего проверок"; Value = $total; Share = (Get-Pct $total $total) }
    [pscustomobject]@{ Metric = "Безопасно"; Value = $safe; Share = (Get-Pct $safe $total) }
    [pscustomobject]@{ Metric = "Осторожно"; Value = $caution; Share = (Get-Pct $caution $total) }
    [pscustomobject]@{ Metric = "Угроза"; Value = $danger; Share = (Get-Pct $danger $total) }
    [pscustomobject]@{ Metric = "Продолжили"; Value = $continued; Share = (Get-Pct $continued $total) }
    [pscustomobject]@{ Metric = "Уник. сайтов"; Value = $hosts; Share = "-" }
    [pscustomobject]@{ Metric = "Дубликаты (пропуск)"; Value = $dupes; Share = "-" }
  )

  $rows | Format-Table -AutoSize | Out-String | ForEach-Object { $_.TrimEnd() }

  if ($s.by_source -and @($s.by_source.PSObject.Properties).Count -gt 0) {
    Write-Host ""
    Write-Host "  По источникам:" -ForegroundColor DarkCyan
    $s.by_source.PSObject.Properties |
      Sort-Object { [int]$_.Value } -Descending |
      ForEach-Object {
        Write-Host ("    {0,-24} {1,5}" -f $_.Name, $_.Value)
      }
  }

  if ($s.last_events -and $s.last_events.Count -gt 0) {
    Write-Host ""
    Write-Host "  Последние события:" -ForegroundColor DarkCyan
    $s.last_events | Select-Object -Last 8 | ForEach-Object {
      $when = "?"
      if ($_.ts) {
        try {
          $when = [DateTimeOffset]::FromUnixTimeSeconds([int64][Math]::Floor([double]$_.ts)).LocalDateTime.ToString("HH:mm:ss")
        } catch {}
      }
      $hostName = if ($_.hostname) { $_.hostname } else { "-" }
      $src = if ($_.source) { $_.source } else { "-" }
      Write-Host ("    {0}  {1,-10}  {2,-28}  {3}" -f $when, $_.status, $hostName, $src)
    }
  }

  if ($s.started_at) {
    try {
      $started = [DateTimeOffset]::FromUnixTimeSeconds([int64][Math]::Floor([double]$s.started_at)).LocalDateTime
      Write-Host ""
      Write-Host ("  Сессия с: {0:dd.MM.yyyy HH:mm}" -f $started) -ForegroundColor DarkGray
    } catch {}
  }
  Write-Host ""
}

if ($Reset) {
  try {
    $null = Invoke-RestMethod -Uri "$base/v1/stats/reset" -Method Post -TimeoutSec 3
    Write-Host "Счётчики сброшены." -ForegroundColor Green
  } catch {
    Write-Host "Не удалось сбросить: $_" -ForegroundColor Red
    exit 1
  }
}

if ($Watch) {
  while ($true) {
    Clear-Host
    Show-Stats (Get-LegionStats)
    Write-Host "  Обновление каждые 3 с · Ctrl+C выход" -ForegroundColor DarkGray
    Start-Sleep -Seconds 3
  }
} else {
  Show-Stats (Get-LegionStats)
}