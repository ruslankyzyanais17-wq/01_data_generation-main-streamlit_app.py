# Offline export only. Does not generate records or change execution policy.
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'generate_dataset.py'
& python $scriptPath @args
exit $LASTEXITCODE
