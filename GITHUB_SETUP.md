# GitHub Setup Guide

This directory is now configured as a Git repository. Follow these steps to sync with GitHub.

## Prerequisites

1. **Install Git for Windows**
   - Download from: https://git-scm.com/download/win
   - Run the installer and accept defaults
   - Open a new PowerShell window to use git commands

2. **GitHub Account**
   - Create account at https://github.com if you don't have one

## Setup Steps

### 1. Install Git (if not already installed)

Download and install Git for Windows from https://git-scm.com/download/win

### 2. Configure Git (first time only)

```powershell
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

### 3. Create Repository on GitHub

1. Go to https://github.com/new
2. Repository name: `intune-stig-delta-analyzer` (or your preferred name)
3. Description: `PowerShell utility for comparing Intune STIG Settings Catalog exports`
4. Choose: Public or Private
5. DO NOT initialize with README, .gitignore, or license (we already have them)
6. Click "Create repository"

### 4. Add Remote and Push Code

After creating the repository on GitHub, you'll see setup instructions. Run these commands in PowerShell:

```powershell
cd C:\REPO\script_comparison

# Add the remote repository (replace USERNAME/REPO with your GitHub user and repo name)
git remote add origin https://github.com/USERNAME/intune-stig-delta-analyzer.git

# Rename branch to main if needed
git branch -M main

# Stage all files
git add .

# Create initial commit
git commit -m "Initial commit: Intune STIG Delta Analyzer"

# Push to GitHub
git push -u origin main
```

### 5. Using SSH (Optional - More Secure)

For SSH authentication (recommended for repeated pushes):

1. Generate SSH key:
```powershell
ssh-keygen -t ed25519 -C "your.email@example.com"
```
Press Enter to accept defaults (creates ~/.ssh/id_ed25519)

2. Add SSH key to SSH agent:
```powershell
$sshAgent = Get-Service ssh-agent -ErrorAction SilentlyContinue
if ($sshAgent.Status -ne 'Running') {
    Start-Service ssh-agent
    Set-Service -Name ssh-agent -StartupType Automatic
}
ssh-add ~/.ssh/id_ed25519
```

3. Add public key to GitHub:
   - Copy contents of ~/.ssh/id_ed25519.pub
   - Go to GitHub Settings → SSH and GPG keys → New SSH key
   - Paste the key and save

4. Update remote to use SSH:
```powershell
git remote set-url origin git@github.com:USERNAME/intune-stig-delta-analyzer.git
```

## Common Git Commands

After initial setup, use these commands to keep your repository in sync:

```powershell
# See status
git status

# Add changes
git add .

# Commit changes
git commit -m "Description of changes"

# Push to GitHub
git push

# Pull latest changes
git pull

# View commit history
git log --oneline
```

## Troubleshooting

**Issue: "git: command not found"**
- Git is not installed or not in PATH
- Restart PowerShell after installing Git
- Verify installation: `git --version`

**Issue: "fatal: 'origin' does not appear to be a 'git' repository"**
- Run: `git remote add origin https://github.com/USERNAME/REPO.git`
- Verify: `git remote -v`

**Issue: "error: src refspec main does not match any"**
- Create initial commit first: `git add . && git commit -m "Initial commit"`
- Then push: `git push -u origin main`

## Next Steps

1. Keep your local copy in sync: `git pull` before making changes
2. Make changes to scripts
3. Commit: `git add . && git commit -m "Description"`
4. Push: `git push`
5. Manage issues and pull requests on GitHub

## Resources

- Git Documentation: https://git-scm.com/doc
- GitHub Docs: https://docs.github.com
- GitHub Setup: https://docs.github.com/en/get-started/quickstart/set-up-git
