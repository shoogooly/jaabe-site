$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$bundledPython = 'C:\Users\Farid\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$pythonCommand = if (Test-Path -LiteralPath $bundledPython) { $bundledPython } else { 'python' }
Set-Location -LiteralPath (Join-Path $projectRoot 'backend')
& $pythonCommand -m uvicorn main:app --reload --host 127.0.0.1 --port 8000

