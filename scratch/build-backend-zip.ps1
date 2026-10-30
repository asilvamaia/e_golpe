Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$projectRoot = "d:\APPS\Fraude"
$zipPath = "$projectRoot\scratch\egolpe-backend-context.zip"

if (-not (Test-Path "$projectRoot\scratch")) {
    New-Item -ItemType Directory -Path "$projectRoot\scratch" | Out-Null
}

if (Test-Path $zipPath) { Remove-Item $zipPath }

$zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)

function Add-ToZip($localFile, $entryName) {
    $fullPath = [System.IO.Path]::GetFullPath($localFile)
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $fullPath, $entryName, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
}

# Root files
Add-ToZip "$projectRoot\.shardcloud" ".shardcloud"
Add-ToZip "$projectRoot\Dockerfile" "Dockerfile"
Add-ToZip "$projectRoot\nginx.conf" "nginx.conf"
Add-ToZip "$projectRoot\start.sh" "start.sh"
Add-ToZip "$projectRoot\requirements.txt" "requirements.txt"
Add-ToZip "$projectRoot\main.py" "main.py"
Add-ToZip "$projectRoot\core.py" "core.py"
Add-ToZip "$projectRoot\app.py" "app.py"
Add-ToZip "$projectRoot\telegram_bot.py" "telegram_bot.py"
Add-ToZip "$projectRoot\simulador.py" "simulador.py"
Add-ToZip "$projectRoot\test_hibp.py" "test_hibp.py"

# Database files
Get-ChildItem -Path "$projectRoot\database" -File | Where-Object { $_.Name -like "*.py" } | ForEach-Object {
    Add-ToZip $_.FullName ("database/" + $_.Name)
}

$zip.Dispose()

$zipSize = (Get-Item $zipPath).Length / 1MB
Write-Host ("Zip criado com sucesso em: {0} ({1:N2} MB)" -f $zipPath, $zipSize)
