# CI/CD Architecture Auditor MVP

This repo now contains a runnable MVP inspired by `deep-research-report.md`.

## What it does

- Scans a repo or sample directory for CI/CD config files:
  - `.github/workflows/*.yml`
  - `.gitlab-ci.yml`
  - `Jenkinsfile`
  - `.circleci/config.yml`
- Applies a dependency-free ruleset focused on high-signal architecture issues:
  - standing cloud secrets
  - missing deploy protections
  - duplicated workflow logic
  - stage-serial pipelines
  - broad runner / credential patterns
  - missing JCasC
  - missing dynamic config / parallelism
- Scores the estate across:
  - security
  - reliability
  - maintainability
  - scalability
  - cost
- Generates:
  - `report.md`
  - `report.html`

## Run it

```bash
python main.py samples/github_monorepo --output-dir out/github
python main.py samples/jenkins_legacy --output-dir out/jenkins
python main.py samples/split_estate --output-dir out/split
```

## Web UI

```bash
python webapp.py
```

Then open `http://127.0.0.1:8000`.

The web UI supports:

- analyzing a local repo path
- uploading a `.zip` archive of a repo
- launching the built-in demo scenarios
- saving and re-importing context as JSON
- project context fields for repo purpose, stack, and target outcome
- copy buttons for findings and migration actions
- per-finding `Plan with Codex` and `Fix with Codex` actions for local path analysis
- checkbox selection plus batch `Plan selected with Codex` / `Fix selected with Codex`
- remediation review screen with prompt preview, approval before apply-mode, and a live job console
- post-run review with changed files, diff preview, and `Accept and Re-audit` / `Revert and Re-audit`
- structured post-run review cards with a remediation timeline and per-file diff sections

## Current MVP boundaries

- Uses heuristic parsing rather than full YAML/Groovy AST parsing.
- GitLab live metadata support is limited to recent pipeline/job fetches; other providers are still config-only.
- Optimized for hackathon demos and local repo analysis, not policy-perfect production audits.
- Codex remediation is currently scoped to one finding at a time from a real local path; uploaded zip analysis stays read-only.

## GitLab recent run metadata

You can enrich the report with recent GitLab pipeline/job history by adding these values to `.env`:

```env
GITLAB_BASE_URL=https://gitlab.example.com
GITLAB_PROJECT=group/project
GITLAB_TOKEN=your_token_here
GITLAB_REF=main
GITLAB_PIPELINE_LIMIT=5
```

Then run the CLI or web UI normally. The auditor will try to fetch recent pipelines/jobs and add:

- a `Recent Run Evidence` section
- extra runtime findings for unstable recent pipelines, repeated failed jobs, and queue delays

## Codex remediation in the web UI

For reports generated from a local repository path, each finding now includes:

- `Copy` for a manual handoff prompt
- `Plan with Codex` for a read-only remediation plan
- `Fix with Codex` to let the local Codex CLI attempt the change directly in the repo

You can also select multiple findings in `Top Findings` and run batch plan/apply actions from the same screen.

Before a write-mode fix starts, the app now shows a review screen with the prompt preview and an approval button.
Once started, a live `Job Console` panel polls remediation status and shows streamed progress logs from the Codex run.
After the run, the same panel shows changed files and a diff preview so you can keep or revert the Codex changes, then re-audit immediately.
The review panel now breaks that down into file cards, file-by-file diff sections, and a small remediation timeline.

## Remediation self-test

You can smoke-test the remediation UI flow against a local repo path with:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\selftest-remediation.ps1 -RepoPath C:\work\dinama-fix
```

That checks:

- report generation for the local repo
- finding selection extraction
- remediation review rendering
- prompt preview and repo path propagation

## Suggested next step

If you want, the next iteration should be either:

1. add a small web server and upload UI
2. add live provider adapters for recent runs
3. expand the ruleset and evidence normalization
