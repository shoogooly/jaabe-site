$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$bundledNode = 'C:\Users\Farid\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe'
$nodeCommand = if (Test-Path -LiteralPath $bundledNode) { $bundledNode } else { 'node' }
Set-Location -LiteralPath (Join-Path $projectRoot 'frontend')
& $nodeCommand '.\node_modules\vite\bin\vite.js' --host 127.0.0.1 --port 5173

