<#
.SYNOPSIS
    ForensIQ Vault — Automated GitHub Sync Utility
.DESCRIPTION
    Automatically stages all changes, creates a commit with the specified
    (or timestamped default) message, and pushes directly to GitHub origin.
.PARAMETER Message
    Optional commit message. Defaults to automated timestamped message.
.EXAMPLE
    .\scripts\auto_sync.ps1 "Updated deliverables"
#>

param (
    [string]$Message = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Message)) {
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $Message = "chore: Automatic sync update - $timestamp"
}

Write-Host "`n⚡ [ForensIQ Vault] Checking repository status..." -ForegroundColor Cyan

# Stage all working changes
git add .

# Check if there is anything to commit
$status = git status --porcelain
if ([string]::IsNullOrWhiteSpace($status)) {
    Write-Host "✔ [ForensIQ Vault] Working tree is clean. Nothing new to commit." -ForegroundColor Green
    
    # Still ensure remote is in sync
    Write-Host "🔄 Verifying remote synchronization..." -ForegroundColor Cyan
    git push origin HEAD
    exit 0
}

Write-Host "💾 Committing changes: '$Message'" -ForegroundColor Yellow
git commit -m "$Message"

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to create commit." -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "🚀 Pushing branch to GitHub origin..." -ForegroundColor Cyan
git push origin HEAD

if ($LASTEXITCODE -eq 0) {
    Write-Host "✔ [ForensIQ Vault] GitHub successfully updated!" -ForegroundColor Green
} else {
    Write-Host "❌ [ForensIQ Vault] Push to GitHub failed." -ForegroundColor Red
    exit $LASTEXITCODE
}
