#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
owner=0xpratikparmar
repo=cyber-sentinel-soc
[[ "$(gh api user --jq .login)" == "$owner" ]] || { echo 'Wrong GitHub account'; exit 1; }
if gh repo view "$owner/$repo" >/dev/null 2>&1; then echo 'Repository already exists; stopping to avoid overwriting.'; exit 1; fi
git init -b main
git add .
git commit -m 'Initial CyberSentinel SOC learning project'
gh repo create "$owner/$repo" --public --source=. --remote=origin --push --description 'Educational browser-local SOC dashboard and security log analysis'
echo "Repository: https://github.com/$owner/$repo"
echo "Enable GitHub Pages from main / root in repository Settings > Pages. Pin manually from your profile."
