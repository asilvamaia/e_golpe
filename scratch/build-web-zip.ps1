Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$projectRoot = "d:\APPS\Fraude\web"
$zipPath = "d:\APPS\Fraude\scratch\egolpe-web-deploy.zip"

if (Test-Path $zipPath) { Remove-Item $zipPath }

$zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)

function Add-ToZip($localFile, $entryName) {
    $fullPath = [System.IO.Path]::GetFullPath($localFile)
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $fullPath, $entryName.Replace('\', '/'), [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
}

Add-ToZip "$projectRoot\.shardcloud" ".shardcloud"
Add-ToZip "$projectRoot\package.json" "package.json"
Add-ToZip "$projectRoot\package-lock.json" "package-lock.json"
Add-ToZip "$projectRoot\next.config.ts" "next.config.ts"
Add-ToZip "$projectRoot\tsconfig.json" "tsconfig.json"

# App folder
Get-ChildItem -Path "$projectRoot\app" -Recurse -File | ForEach-Object {
    $rel = $_.FullName.Substring($projectRoot.Length + 1)
    Add-ToZip $_.FullName $rel
}

# .next folder (exclude cache)
Get-ChildItem -Path "$projectRoot\.next" -Recurse -File | Where-Object { $_.FullName -notmatch "[\/\\]cache[\/\\]" } | ForEach-Object {
    $rel = $_.FullName.Substring($projectRoot.Length + 1)
    Add-ToZip $_.FullName $rel
}

$zip.Dispose()

$zipSize = (Get-Item $zipPath).Length / 1MB
Write-Host ("Zip do frontend criado com sucesso em: {0} ({1:N2} MB)" -f $zipPath, $zipSize)
