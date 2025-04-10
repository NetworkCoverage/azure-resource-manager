param (
    [string]$RepositoryUrl = "https://github.com/YourOrganization/YourRepository.git",
    [string]$ScriptToRun = "scripts/setup.ps1"
)

# Extract repo name from URL
$repoName = ($RepositoryUrl -split "/")[-1].Replace(".git", "")

# Clone if it doesn't already exist
if (-not (Test-Path -Path "./$repoName")) {
    Write-Host "📥 Cloning repository: $RepositoryUrl"
    git clone $RepositoryUrl
} else {
    Write-Host "📁 Repository already exists. Skipping clone."
}

# Navigate into the repository
Set-Location -Path "./$repoName"

# Confirm script exists
if (-not (Test-Path -Path $ScriptToRun)) {
    Write-Error "❌ Script '$ScriptToRun' not found in the repository."
    exit 1
}

# Execute the script
Write-Host "▶️ Running script: $ScriptToRun"
& $ScriptToRun