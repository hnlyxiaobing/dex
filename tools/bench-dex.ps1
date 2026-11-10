# bench-dex.ps1 -- dex 真实规模性能门禁（P0 D2，fail-closed，第六道可选显式门禁）。
#
# 定位与 CI 裁决（写进注释，不修改任何 ci.yml）：
#   工作区根 .github/workflows/ci.yml:22-27 已有明确裁决「不增设机械第 6 道门禁」，
#   且 11 份模块 ci.yml 云上 11/11 全绿。本门禁定位为「第六道可选显式门禁」：
#   本地 / CI 显式调用的独立脚本，不挂进既有五道门禁链路
#   （moon check --deny-warn / moon build / moon test / moon fmt --check /
#    moon info && git diff --exit-code 快照一致性）。
#   理由：GitHub Actions ubuntu-latest 为共享机型，绝对时间阈值会造成 flaky
#   假阳性，把防回归门禁变成随机回归；而 5s 阈值相对本地实测约 1s 有 5 倍
#   余量，本地可稳定捕获 O(C x T) 回退（旧实现逐类重建全表，本合成 DEX 上
#   实测约 17s，修复后约 0.06s）。故保持五道门禁链路不动，本脚本仅显式调用。
#
# Usage:  pwsh -File tools/bench-dex.ps1 [-Cli <exe路径>] [-WorkDir <dir>]
#         从模块根 dex/ 运行；亦可用 powershell -File（PowerShell 5.1 兼容）。
#         默认 -Cli = <模块根>/_build/native/release/build/cmd/main/main.exe
#         默认 -WorkDir = 系统临时目录/dex-bench（合成产物不入库）。
# Exit:   0 = PASSED；1 = FAILED（FAILED 逐条 "  - <原因>"）。
#
# 阈值（绝对上限，毫秒；报告 §3 D2 口径）：summary < 5000、norm < 10000。
#   gen-large-dex.py 生成约 4000 个 class_def / 6000 条字符串的合法 DEX 035，
#   每类带 annotation_directory_item（1 个类注解）与 static_values encoded_array。
#
# fail-closed 语义（不早退、无 skip 分支、任何异常都进 $failures）：
#   CLI 退出码非 0、输出文件缺失/为空、Python 生成器失败、计时/类数未解析到、
#   进程超时（默认 60s）、确定性下限断言不满足（summary 的 CLZ|/ANN|/SVC| 行数
#   各 >= 生成类数）、绝对阈值超限，全部计入 $failures，最后统一判定。

param(
  [string]$Cli = '',
  [string]$WorkDir = '',
  [int]$TimeoutMs = 60000
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$moduleRoot = Split-Path -Parent $PSScriptRoot
$genScript = Join-Path $PSScriptRoot 'gen-large-dex.py'
if ($Cli -eq '') {
  $Cli = Join-Path $moduleRoot '_build/native/release/build/cmd/main/main.exe'
}
if ($WorkDir -eq '') {
  $WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) 'dex-bench'
}
# 相对 -Cli 先按当前目录，再按工作区根（模块根的父目录）尝试，便于两种运行方式。
if (-not [System.IO.Path]::IsPathRooted($Cli) -and -not (Test-Path -LiteralPath $Cli)) {
  $altCli = Join-Path (Split-Path -Parent $moduleRoot) $Cli
  if (Test-Path -LiteralPath $altCli) { $Cli = $altCli }
}

# 合成规模固定（约 3000-5000 类；字符串池数千条，使逐类重建全表明显退化）。
$classes = 4000
$stringsCount = 6000

$thresholdsMs = [ordered]@{
  'summary' = 5000.0
  'norm'    = 10000.0
}

$failures = New-Object System.Collections.Generic.List[string]
$results = [ordered]@{}

# --- workdir（合成产物不入库） ---------------------------------------------
try {
  New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
} catch {
  $failures.Add("workdir 无法创建 ($WorkDir): $($_.Exception.Message)")
}
$dexPath = Join-Path $WorkDir 'large.dex'

# --- 1) 调用生成器（命令输出 2>&1 | Out-String + $LASTEXITCODE） -----------
$genOutput = ''
$genExit = 1
try {
  $genOutput = (& python $genScript --out $dexPath --classes $classes --strings $stringsCount 2>&1 | Out-String)
  $genExit = $LASTEXITCODE
} catch {
  $failures.Add("gen-large-dex.py 无法执行: $($_.Exception.Message)")
}
if ($genExit -ne 0 -and $failures.Count -eq 0) {
  $failures.Add("gen-large-dex.py 退出码 $genExit (输出: $($genOutput.Trim()))")
}

# 解析「生成类数」（解析不到即失败，fail-closed）。
$genClasses = 0
if ($genOutput -match 'GEN\|classes=(\d+)\|strings=(\d+)\|size=(\d+)\|sha256=([0-9a-f]{64})') {
  $genClasses = [int]$Matches[1]
} else {
  $failures.Add("gen-large-dex.py 输出未解析到 GEN|classes=... (fail-closed)")
}

# --- 2) 校验文件大小与魔数 -------------------------------------------------
if (-not (Test-Path -LiteralPath $dexPath)) {
  $failures.Add("生成的 DEX 文件缺失: $dexPath")
} else {
  $dexLen = (Get-Item -LiteralPath $dexPath).Length
  if ($dexLen -lt 100000) {
    $failures.Add("生成的 DEX 过小: $dexLen bytes (< 100000)")
  }
  $expectedMagic = [byte[]]@(0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00)
  $magic = New-Object byte[] 8
  $fs = $null
  try {
    $fs = [System.IO.File]::OpenRead($dexPath)
    $read = $fs.Read($magic, 0, 8)
    $magicOk = $read -eq 8
    if ($magicOk) {
      for ($i = 0; $i -lt 8; $i++) {
        if ($magic[$i] -ne $expectedMagic[$i]) { $magicOk = $false; break }
      }
    }
    if (-not $magicOk) {
      $failures.Add('生成的 DEX 魔数/版本不符 (期望 dex 035 magic)')
    }
  } catch {
    $failures.Add("生成的 DEX 魔数读取失败: $($_.Exception.Message)")
  } finally {
    if ($null -ne $fs) { $fs.Dispose() }
  }
}

# --- 3) 计时 + 超时保护 + 输出重定向到文件 ---------------------------------
function Invoke-DexDump {
  param(
    [string]$View,
    [string]$OutPath,
    [string]$ErrPath
  )
  $result = [ordered]@{
    Ran       = $false
    TimedOut  = $false
    ExitCode  = -1
    ElapsedMs = -1.0
    Error     = ''
  }
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $p = $null
  try {
    # 直接用 .NET Process（不经过 Start-Process 的环境变量复制，规避
    # HTTPS_PROXY / https_proxy 大小写冲突导致的 "已添加项" 异常）。
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Cli
    $psi.Arguments = 'dump "' + $dexPath + '" --view ' + $View
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $psi.CreateNoWindow = $true
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    $null = $p.Start()
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutMs)) {
      $result.TimedOut = $true
      try { $p.Kill() } catch { }
      $p.WaitForExit()
    }
    $result.ExitCode = $p.ExitCode
    # 输出重定向到文件（任务要求）；超时后不强等异步流。
    if ($outTask.Wait(5000)) {
      [System.IO.File]::WriteAllText($OutPath, $outTask.Result)
    }
    if ($errTask.Wait(5000)) {
      [System.IO.File]::WriteAllText($ErrPath, $errTask.Result)
    }
    $result.Ran = $true
  } catch {
    $result.Error = $_.Exception.Message
  } finally {
    $sw.Stop()
    if ($result.Ran) {
      $result.ElapsedMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
    }
    if ($null -ne $p) { $p.Dispose() }
  }
  return [pscustomobject]$result
}

foreach ($view in $thresholdsMs.Keys) {
  $outPath = Join-Path $WorkDir ("dump-$view.out.txt")
  $errPath = Join-Path $WorkDir ("dump-$view.err.txt")
  foreach ($f in @($outPath, $errPath)) {
    if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
  }

  $r = Invoke-DexDump -View $view -OutPath $outPath -ErrPath $errPath
  if (-not $r.Ran) {
    $failures.Add("dump --view $view 无法执行: $($r.Error)")
  } else {
    if ($r.TimedOut) {
      $failures.Add("dump --view $view 超时 ${TimeoutMs} ms (fail-closed)")
    }
    if ($r.ExitCode -ne 0) {
      $failures.Add("dump --view $view 退出码 $($r.ExitCode)")
    }
  }
  if ($r.ElapsedMs -lt 0) {
    $failures.Add("dump --view $view 计时未解析到 (fail-closed)")
  }

  # 输出文件存在 / 非空 + 记录行统计
  $lineCount = 0
  $clzCount = 0
  $annCount = 0
  $svcCount = 0
  if (-not (Test-Path -LiteralPath $outPath)) {
    $failures.Add("dump --view $view 输出文件缺失: $outPath")
  } else {
    $outLen = (Get-Item -LiteralPath $outPath).Length
    if ($outLen -le 0) {
      $failures.Add("dump --view $view 输出文件为空")
    }
    $lineCount = @(Get-Content -LiteralPath $outPath).Count
    $clzCount = @(Select-String -LiteralPath $outPath -Pattern '^CLZ\|').Count
    $annCount = @(Select-String -LiteralPath $outPath -Pattern '^ANN\|').Count
    $svcCount = @(Select-String -LiteralPath $outPath -Pattern '^SVC\|').Count
  }

  # 绝对阈值（报告 §3 D2）
  $limit = [double]$thresholdsMs[$view]
  if ($r.ElapsedMs -ge 0 -and $r.ElapsedMs -gt $limit) {
    $failures.Add("dump --view $view 耗时 $($r.ElapsedMs) ms > 阈值 $limit ms")
  }

  # 确定性下限断言（仅 summary）：防假通过，缺任一即失败
  if ($view -eq 'summary' -and $genClasses -gt 0) {
    if ($clzCount -lt $genClasses) {
      $failures.Add("summary CLZ| 行数 $clzCount < 生成类数 $genClasses (fail-closed)")
    }
    if ($annCount -lt $genClasses) {
      $failures.Add("summary ANN| 行数 $annCount < 生成类数 $genClasses (fail-closed)")
    }
    if ($svcCount -lt $genClasses) {
      $failures.Add("summary SVC| 行数 $svcCount < 生成类数 $genClasses (fail-closed)")
    }
  }

  $results[$view] = [pscustomobject]@{
    ElapsedMs = $r.ElapsedMs
    Lines     = $lineCount
    Ann       = $annCount
    Svc       = $svcCount
  }
}

# --- 4) 汇总 + 判定（固定前缀 bench-dex:） ---------------------------------
Write-Host 'bench-dex: measured dump times (ms) / lines / ANN / SVC'
foreach ($view in $results.Keys) {
  $r = $results[$view]
  Write-Host ("bench-dex:   {0,-8} {1,10:N1} ms  lines={2,-7} ANN={3,-6} SVC={4,-6} limit={5} ms" -f `
      $view, $r.ElapsedMs, $r.Lines, $r.Ann, $r.Svc, $thresholdsMs[$view])
}
if ($failures.Count -gt 0) {
  Write-Host 'bench-dex: FAILED'
  foreach ($f in $failures) { Write-Host "  - $f" }
  exit 1
}
Write-Host "bench-dex: PASSED (classes=$genClasses strings=$stringsCount; CLZ/ANN/SVC >= $genClasses; summary<5000 ms / norm<10000 ms)"
exit 0
