$ErrorActionPreference = "Stop"

$envFile = Join-Path $PSScriptRoot ".env"
if (!(Test-Path $envFile)) {
    throw "Missing .env file at $envFile"
}

$pairs = @{}
foreach ($line in Get-Content $envFile) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith("#")) {
        continue
    }
    $name, $value = $trimmed -split "=", 2
    if ($name) {
        if ($null -eq $value) {
            $value = ""
        }
        $pairs[$name.Trim()] = $value.Trim()
    }
}

$ghToken = $pairs["GH_TOKEN"]
$owner = $pairs["GITHUB_OWNER"]
$repo = $pairs["GITHUB_REPO"]

if (-not $ghToken) {
    throw "GH_TOKEN is empty in .env"
}
if (-not $owner) {
    throw "GITHUB_OWNER is empty in .env"
}
if (-not $repo) {
    throw "GITHUB_REPO is empty in .env"
}

$env:GH_TOKEN = $ghToken

gh auth status | Out-Null

$repoName = "$owner/$repo"
$view = $null
try {
    $view = gh repo view $repoName --json nameWithOwner -q .nameWithOwner 2>$null
} catch {
    $view = $null
}
if (-not $view) {
    gh repo create $repoName --private --source . --remote origin --push
} else {
    $remoteUrl = "https://github.com/$repoName.git"
    $hasOrigin = git remote
    if ($hasOrigin -notcontains "origin") {
        git remote add origin $remoteUrl
    }
    git push -u origin main
}

Write-Output "Published to https://github.com/$repoName"
