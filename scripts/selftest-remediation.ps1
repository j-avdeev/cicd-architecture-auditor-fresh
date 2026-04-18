param(
    [string]$RepoPath = "C:\work\dinama-fix",
    [string]$BaseUrl = "http://127.0.0.1:8000"
)

$ErrorActionPreference = "Stop"

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

$analyze = Invoke-WebRequest -Uri "$BaseUrl/analyze" -Method Post -Body @{ target_path = $RepoPath } -UseBasicParsing
Assert-True ($analyze.StatusCode -eq 200) "Analyze request failed."

$content = $analyze.Content
$keyMatch = [regex]::Match($content, "name='selected_finding' value='([^']+)'")
Assert-True $keyMatch.Success "No selectable finding was found in the report."
$selectedFinding = $keyMatch.Groups[1].Value

$review = Invoke-WebRequest -Uri "$BaseUrl/remediation-review" -Method Post -Body @{
    target_path = $RepoPath
    mode = "plan"
    project_description = "Self-test target"
    project_stack = "GitLab CI"
    project_goals = "Verify remediation flow"
    selected_finding = $selectedFinding
} -UseBasicParsing

Assert-True ($review.StatusCode -eq 200) "Remediation review request failed."
Assert-True (($review.Content -match "Remediation Review")) "Review panel did not render."
Assert-True (($review.Content -match [regex]::Escape($RepoPath))) "Repo path did not survive into the remediation review."
Assert-True (($review.Content -match "Prompt Preview")) "Prompt preview did not render."

Write-Output "Remediation self-test passed for $RepoPath"
