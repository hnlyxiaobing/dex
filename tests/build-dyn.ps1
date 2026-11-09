# Controlled sample build script (fx-dyn: 038+ opcode group + payload semantics).
# Usage (from dex/ module root): powershell -File tests/build-dyn.ps1 [-Update]
# Output: tests/fixtures/fx-dyn.classes.dex (d8 --min-api 26 keeps invoke-custom/indy).
# Tool versions are recorded in tests/ASSETS.md (javac 21.0.9 / d8 8.6.2-dev / android-35).
param([switch]$Update)
$ErrorActionPreference = 'Stop'
$work = Join-Path $PSScriptRoot 'work'              # dex/tests/work (not committed)
$fixDir = Join-Path $PSScriptRoot 'fixtures'
$javac = 'C:\Program Files\Java\jdk-21\bin\javac.exe'
$d8 = 'D:\Android\Sdk\build-tools\35.0.0\d8.bat'
$androidJar = 'D:\Android\Sdk\platforms\android-35\android.jar'
$env:JAVA_HOME = 'C:\Program Files\Java\jdk-21'
New-Item -ItemType Directory -Force -Path $work | Out-Null
Get-ChildItem $work -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
& $javac --release 11 -encoding UTF-8 -cp $androidJar -d (Join-Path $work 'classes') (Join-Path $PSScriptRoot 'src\FxDyn.java')
if ($LASTEXITCODE -ne 0) { throw "javac failed: $LASTEXITCODE" }
# --no-desugaring keeps lambdas as invokedynamic (invoke-custom + call_site_id_item).
& $d8 --min-api 26 --no-desugaring --lib $androidJar --output $work (Join-Path $work 'classes\fx\dyn\FxDyn.class') (Join-Path $work 'classes\fx\dyn\FxDyn$IntOp.class')
if ($LASTEXITCODE -ne 0) { throw "d8 failed: $LASTEXITCODE" }
$src = Join-Path $work 'classes.dex'
$dst = Join-Path $fixDir 'fx-dyn.classes.dex'
$sha = (Get-FileHash $src -Algorithm SHA256).Hash
Write-Output "built $src sha256=$sha"
if ($Update) {
  Copy-Item $src $dst -Force
  Write-Output "updated $dst"
} else {
  if ((Get-FileHash $dst -Algorithm SHA256).Hash -ne $sha) { Write-Output 'DIFF: fixture differs from fresh build' } else { Write-Output 'OK: fixture == fresh build' }
}
