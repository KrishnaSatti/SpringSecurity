#RUN WITH .\CopyJavaFiles.ps1

# Define the paths
$sourcePath = "src\main\java"
$destinationPath = "project"

# Check if the destination folder exists and empty it
if (Test-Path -Path $destinationPath) {
    Remove-Item -Recurse -Force "$destinationPath\*"
} else {
    # Create the destination folder if it does not exist
    New-Item -ItemType Directory -Force -Path $destinationPath
}

# Copy all files from the source path to the destination path
Get-ChildItem -Path $sourcePath -Recurse -File | ForEach-Object {
    Copy-Item -Path $_.FullName -Destination $destinationPath -Force
}

Write-Output "Files copied to the $destinationPath folder successfully."
