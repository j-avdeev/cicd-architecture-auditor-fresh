from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from pathlib import Path

from auditor.models import AnalysisResult, Evidence, Finding, RecentRuns, SourceFile, WEIGHTS


def line_matches(source: SourceFile, pattern: str) -> list[Evidence]:
    hits: list[Evidence] = []
    for index, line in enumerate(source.lines, start=1):
        if pattern.lower() in line.lower():
            hits.append(
                Evidence(
                    path=source.path.as_posix(),
                    line=index,
                    snippet=line.strip(),
                )
            )
    return hits


def has_any(text: str, needles: list[str]) -> bool:
    lowered = text.lower()
    return any(needle.lower() in lowered for needle in needles)


def normalized_workflow_shape(source: SourceFile) -> str:
    lines = []
    for raw in source.lines:
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"\$\{\{.*?\}\}", "${expr}", line)
        line = re.sub(r"[a-f0-9]{8,40}", "${sha}", line)
        line = re.sub(r"deploy-service-[a-z0-9_-]+", "deploy-service-x", line)
        line = re.sub(r"deploy-[a-z0-9_-]+\.sh", "deploy-x.sh", line)
        line = re.sub(r"(npm|pnpm|yarn)\s+(ci|install|test)", "pkgcmd", line)
        line = re.sub(r"\s+", " ", line)
        lines.append(line)
    return hashlib.sha1("\n".join(lines).encode("utf-8")).hexdigest()


def github_rules(files: list[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    grouped: dict[str, list[SourceFile]] = defaultdict(list)
    aws_evidence: list[Evidence] = []
    missing_environment: list[Evidence] = []
    missing_concurrency: list[Evidence] = []
    missing_provenance: list[Evidence] = []

    for source in [f for f in files if f.kind == "github"]:
        grouped[normalized_workflow_shape(source)].append(source)

        aws_hits = line_matches(source, "AWS_ACCESS_KEY_ID") + line_matches(source, "AWS_SECRET_ACCESS_KEY")
        if aws_hits and has_any(source.text, ["secrets.AWS_ACCESS_KEY_ID", "secrets.AWS_SECRET_ACCESS_KEY"]):
            aws_evidence.extend(aws_hits[:2])

        if has_any(source.text, ["deploy", "release"]) and "environment:" not in source.text:
            missing_environment.append(
                line_matches(source, "deploy")[:1][0]
                if line_matches(source, "deploy")[:1]
                else Evidence(source.path.as_posix(), None, "Deploy-like workflow detected without environment key.")
            )

        if has_any(source.text, ["deploy", "release", "prod"]) and "concurrency:" not in source.text:
            missing_concurrency.append(
                line_matches(source, "name:")[:1][0]
                if line_matches(source, "name:")[:1]
                else Evidence(source.path.as_posix(), None, "Deploy-like workflow detected without concurrency.")
            )

        if has_any(source.text, ["deploy", "release"]) and not has_any(source.text, ["attest", "provenance", "build-provenance"]):
            missing_provenance.append(
                Evidence(source.path.as_posix(), None, "Release-like workflow detected without attestation keywords.")
            )

    if aws_evidence:
        findings.append(
            Finding(
                rule_id="GH001",
                title="Long-lived AWS secrets in GitHub workflows",
                severity="critical",
                dimension="security",
                summary="Deployment workflows rely on stored AWS access keys instead of ephemeral federation.",
                impact="Compromised repository or workflow access can expose standing cloud credentials across multiple services.",
                recommendation="Replace static AWS secrets with GitHub OIDC federation and a narrowly scoped cloud role.",
                phase="Phase A: Hardening",
                confidence="high",
                framework_refs=["OWASP CI/CD-SEC-6", "SLSA", "SSDF"],
                evidence=aws_evidence[:4],
            )
        )

    if missing_environment:
        findings.append(
            Finding(
                rule_id="GH002",
                title="GitHub deploy workflows lack protected environments",
                severity="high",
                dimension="security",
                summary="Deployment workflows do not declare environments for protection rules.",
                impact="Production jobs can run without required reviewers or environment-specific restrictions.",
                recommendation="Route deploy jobs through protected environments with reviewer and branch controls.",
                phase="Phase A: Hardening",
                confidence="medium",
                framework_refs=["OWASP CI/CD-SEC-4", "SSDF"],
                evidence=missing_environment[:4],
            )
        )

    if missing_concurrency:
        findings.append(
            Finding(
                rule_id="GH003",
                title="GitHub deploy workflows lack concurrency guards",
                severity="medium",
                dimension="reliability",
                summary="Deployment workflows do not define concurrency groups.",
                impact="Concurrent runs can overlap on the same target and increase rollback or drift risk.",
                recommendation="Add concurrency groups around production targets and cancel stale in-flight runs where appropriate.",
                phase="Phase A: Hardening",
                confidence="medium",
                framework_refs=["DORA"],
                evidence=missing_concurrency[:4],
            )
        )

    if missing_provenance:
        findings.append(
            Finding(
                rule_id="GH004",
                title="GitHub release flows lack provenance signals",
                severity="medium",
                dimension="security",
                summary="Release-oriented workflows show no sign of artifact attestation or provenance generation.",
                impact="Artifact origin is harder to validate during incident response or policy enforcement.",
                recommendation="Emit and verify artifact attestations for release outputs where your platform supports it.",
                phase="Phase C: Scale Optimization",
                confidence="low",
                framework_refs=["SLSA"],
                evidence=missing_provenance[:4],
            )
        )

    for duplicates in grouped.values():
        if len(duplicates) > 1:
            evidence = [Evidence(item.path.as_posix(), None, "Near-duplicate workflow detected.") for item in duplicates[:3]]
            findings.append(
                Finding(
                    rule_id="GH005",
                    title="Near-duplicate GitHub workflows should be centralized",
                    severity="high",
                    dimension="maintainability",
                    summary="Multiple GitHub workflows share the same structure and differ only in service-specific commands.",
                    impact="Copy-pasted deployment logic makes governance, fixes, and upgrades slower and riskier.",
                    recommendation="Collapse duplicated workflows into a reusable workflow with service-specific inputs.",
                    phase="Phase B: Standardization",
                    confidence="high",
                    framework_refs=["DORA"],
                    evidence=evidence,
                )
            )

    return findings


def gitlab_rules(files: list[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    for source in [f for f in files if f.kind == "gitlab"]:
        stage_count = len(line_matches(source, "stage:"))
        needs_count = len(line_matches(source, "needs:"))
        if "stages:" in source.text and stage_count >= 3 and needs_count <= 1:
            findings.append(
                Finding(
                    rule_id="GL001",
                    title="GitLab pipeline is mostly stage-serial",
                    severity="high",
                    dimension="scalability",
                    summary="Pipeline defines multiple stages but shows little or no DAG dependency usage with `needs`.",
                    impact="Jobs wait for whole stages instead of flowing as soon as dependencies are complete.",
                    recommendation="Introduce `needs`-based DAG execution and split large flows into child pipelines or components.",
                    phase="Phase C: Scale Optimization",
                    confidence="high",
                    framework_refs=["DORA"],
                    evidence=(line_matches(source, "stages:")[:1] + line_matches(source, "needs:")[:1])[:2],
                )
            )

        if has_any(source.text, ["deploy", "deploy_prod"]) and "environment:" not in source.text:
            findings.append(
                Finding(
                    rule_id="GL002",
                    title="GitLab deploy job lacks explicit environment controls",
                    severity="high",
                    dimension="security",
                    summary="Deploy job is present without an explicit environment declaration.",
                    impact="Protected environment policies and deploy-specific approvals are harder to enforce.",
                    recommendation="Declare protected environments for production deploys and scope variables to those environments.",
                    phase="Phase A: Hardening",
                    confidence="medium",
                    framework_refs=["OWASP CI/CD-SEC-4", "SSDF"],
                    evidence=line_matches(source, "deploy")[:2],
                )
            )

        if has_any(source.text, ["allowunencryptedauthentication", "-authentication basic", "curl.exe", "invoke-webrequest"]):
            findings.append(
                Finding(
                    rule_id="GL003",
                    title="GitLab jobs use basic-auth artifact transport",
                    severity="high",
                    dimension="security",
                    summary="Pipeline scripts upload or download artifacts with basic authentication patterns.",
                    impact="Credential handling is harder to constrain and can leak through logs, process lists, or runner state.",
                    recommendation="Replace basic-auth transfers with scoped job tokens, package registry auth, or short-lived service credentials.",
                    phase="Phase A: Hardening",
                    confidence="high",
                    framework_refs=["OWASP CI/CD-SEC-6", "SSDF"],
                    evidence=(line_matches(source, "Authentication Basic") + line_matches(source, "AllowUnencryptedAuthentication") + line_matches(source, "curl.exe"))[:4],
                )
            )

        token_url_hits = []
        for index, line in enumerate(source.lines, start=1):
            lower = line.lower()
            if "git clone" in lower and "@" in line and ("glpat-" in lower or "http" in lower):
                token_url_hits.append(Evidence(source.path.as_posix(), index, line.strip()))
        if token_url_hits:
            findings.append(
                Finding(
                    rule_id="GL004",
                    title="GitLab pipeline embeds credentials in clone URL",
                    severity="critical",
                    dimension="security",
                    summary="Pipeline clones a repository using a URL that appears to contain a username/token pair.",
                    impact="Secrets can leak via CI config, logs, job traces, or copied command history.",
                    recommendation="Move repository access to masked CI variables or native job-token based authentication without inline secrets in URLs.",
                    phase="Phase A: Hardening",
                    confidence="high",
                    framework_refs=["OWASP CI/CD-SEC-6", "SSDF"],
                    evidence=token_url_hits[:3],
                )
            )

        destructive_hits = line_matches(source, "Remove-Item -Recurse -Force")
        if destructive_hits:
            findings.append(
                Finding(
                    rule_id="GL005",
                    title="GitLab jobs perform destructive recursive cleanup",
                    severity="medium",
                    dimension="reliability",
                    summary="Pipeline scripts delete directories recursively in-place on the runner.",
                    impact="On persistent Windows runners, cleanup mistakes can damage shared state and create flaky cross-job behavior.",
                    recommendation="Use isolated workspaces or tighter path-checked cleanup steps instead of broad recursive deletes on persistent runners.",
                    phase="Phase C: Scale Optimization",
                    confidence="medium",
                    framework_refs=["DORA"],
                    evidence=destructive_hits[:4],
                )
            )

        tag_hits = line_matches(source, 'tags:')
        win_hits = line_matches(source, '"win10"') + line_matches(source, "win10")
        if tag_hits and win_hits:
            findings.append(
                Finding(
                    rule_id="GL006",
                    title="GitLab pipeline is pinned to a specific Windows runner tag",
                    severity="medium",
                    dimension="scalability",
                    summary="The pipeline appears tightly coupled to a specific tagged Windows runner pool.",
                    impact="Execution capacity and portability are constrained, which can increase queueing and operational burden.",
                    recommendation="Document why a fixed runner tag is required and isolate only the truly Windows-bound jobs from more elastic workloads.",
                    phase="Phase C: Scale Optimization",
                    confidence="medium",
                    framework_refs=["DORA"],
                    evidence=(tag_hits + win_hits)[:3],
                )
            )

        manual_hits = line_matches(source, "when: manual")
        if manual_hits:
            findings.append(
                Finding(
                    rule_id="GL007",
                    title="GitLab pipeline uses manual publish gating",
                    severity="medium",
                    dimension="reliability",
                    summary="A job in the packaging path is configured as manual instead of flowing through policy-based automation.",
                    impact="Release readiness depends on human intervention, which can create drift between commits, artifacts, and test runs.",
                    recommendation="Use explicit protected-branch rules and promotion conditions so packaging follows a deterministic release path instead of a manual click step.",
                    phase="Phase B: Standardization",
                    confidence="medium",
                    framework_refs=["DORA"],
                    evidence=(line_matches(source, "rules:")[:1] + manual_hits[:2]),
                )
            )

        hardcoded_runtime_hits = []
        for needle in ['C:\\DINAMA', 'C:\\DINAMA\\python\\python.exe', 'GitLab-Runner\\builds\\qs3GasnjE', '$env:DINSYS\\DINAMA']:
            hardcoded_runtime_hits.extend(line_matches(source, needle))
        if hardcoded_runtime_hits:
            findings.append(
                Finding(
                    rule_id="GL008",
                    title="GitLab jobs depend on hard-coded runner filesystem paths",
                    severity="high",
                    dimension="maintainability",
                    summary="Pipeline logic assumes specific Windows directory layouts and runner-local absolute paths.",
                    impact="Jobs become brittle across runners, hard to reproduce locally, and expensive to migrate to cleaner worker images.",
                    recommendation="Replace absolute runner paths with workspace-relative locations, CI variables, and job artifacts passed between stages.",
                    phase="Phase B: Standardization",
                    confidence="high",
                    framework_refs=["SSDF", "DORA"],
                    evidence=hardcoded_runtime_hits[:5],
                )
            )

        dependency_hits = line_matches(source, "dependencies:")
        if dependency_hits:
            findings.append(
                Finding(
                    rule_id="GL009",
                    title="GitLab pipeline still relies on legacy artifact dependencies",
                    severity="medium",
                    dimension="maintainability",
                    summary="The pipeline wires jobs together with `dependencies` instead of a clearer DAG-driven handoff.",
                    impact="Artifact flow is harder to reason about, and pipeline execution stays more coupled to stage ordering than necessary.",
                    recommendation="Move artifact handoff to `needs`-based job relationships so execution order and artifact contracts are explicit.",
                    phase="Phase B: Standardization",
                    confidence="medium",
                    framework_refs=["DORA"],
                    evidence=(dependency_hits[:1] + line_matches(source, "result.xml")[:2]),
                )
            )

        oversized_block_evidence: list[Evidence] = []
        current_block_start = None
        current_block_size = 0
        for index, line in enumerate(source.lines, start=1):
            if line.strip() == "- |":
                current_block_start = index
                current_block_size = 0
                continue
            if current_block_start is not None:
                if re.match(r"^\s{2,}[A-Za-z0-9_-]+:\s*$", line):
                    if current_block_size >= 20:
                        oversized_block_evidence.append(
                            Evidence(source.path.as_posix(), current_block_start, f"Inline PowerShell block spans about {current_block_size} lines.")
                        )
                    current_block_start = None
                    current_block_size = 0
                else:
                    current_block_size += 1
        if current_block_start is not None and current_block_size >= 20:
            oversized_block_evidence.append(
                Evidence(source.path.as_posix(), current_block_start, f"Inline PowerShell block spans about {current_block_size} lines.")
            )
        if oversized_block_evidence:
            findings.append(
                Finding(
                    rule_id="GL010",
                    title="GitLab pipeline contains oversized inline PowerShell blocks",
                    severity="medium",
                    dimension="maintainability",
                    summary="Large operational scripts are embedded directly in `.gitlab-ci.yml` instead of being versioned as reusable script files.",
                    impact="Reviewing, testing, and reusing CI behavior becomes slower, and small changes carry a larger blast radius.",
                    recommendation="Extract long PowerShell blocks into versioned `.ps1` scripts and keep the CI YAML focused on orchestration.",
                    phase="Phase B: Standardization",
                    confidence="high",
                    framework_refs=["DORA"],
                    evidence=oversized_block_evidence[:4],
                )
            )

        hardcoded_result_hits = line_matches(source, "result.xml")
        runner_build_path_hits = line_matches(source, "GitLab-Runner\\builds\\")
        if hardcoded_result_hits and runner_build_path_hits:
            findings.append(
                Finding(
                    rule_id="GL011",
                    title="GitLab test report handoff depends on a hard-coded runner build path",
                    severity="high",
                    dimension="reliability",
                    summary="The pipeline moves `result.xml` into a runner-specific build directory instead of leaving it in the job workspace.",
                    impact="JUnit report collection can break when runner IDs, checkout paths, or executor layouts change.",
                    recommendation="Keep `result.xml` in the job workspace and declare it directly in `artifacts:reports:junit` without runner-specific move steps.",
                    phase="Phase A: Hardening",
                    confidence="high",
                    framework_refs=["DORA"],
                    evidence=(hardcoded_result_hits[:3] + runner_build_path_hits[:1])[:4],
                )
            )

    return findings


def circleci_rules(files: list[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    for source in [f for f in files if f.kind == "circleci"]:
        context_hits = line_matches(source, "context:")
        if any("global" in hit.snippet.lower() for hit in context_hits):
            findings.append(
                Finding(
                    rule_id="CC001",
                    title="CircleCI workflow uses broad global context",
                    severity="high",
                    dimension="security",
                    summary="A CircleCI job references a global context that appears to include production credentials.",
                    impact="Credentials may be exposed to too many jobs, branches, or engineers.",
                    recommendation="Replace broad contexts with restricted, environment-specific contexts and context policies.",
                    phase="Phase A: Hardening",
                    confidence="medium",
                    framework_refs=["OWASP CI/CD-SEC-6", "SSDF"],
                    evidence=context_hits[:2],
                )
            )

        if "setup: true" not in source.text:
            findings.append(
                Finding(
                    rule_id="CC002",
                    title="CircleCI config does not use dynamic setup",
                    severity="medium",
                    dimension="cost",
                    summary="CircleCI config appears static, so full flows may run on irrelevant changes.",
                    impact="Teams can burn credits and wait longer for jobs that do not need to run.",
                    recommendation="Use dynamic configuration to route only the workflows needed for a given change set.",
                    phase="Phase C: Scale Optimization",
                    confidence="low",
                    framework_refs=["DORA"],
                    evidence=[Evidence(source.path.as_posix(), None, "No `setup: true` detected.")],
                )
            )

        if has_any(source.text, ["yarn test", "npm test", "gradlew test"]) and "parallelism:" not in source.text:
            findings.append(
                Finding(
                    rule_id="CC003",
                    title="CircleCI test flow lacks parallelism",
                    severity="medium",
                    dimension="scalability",
                    summary="Test-heavy CircleCI job does not declare parallelism.",
                    impact="Feedback loops stay slower than necessary as the test suite grows.",
                    recommendation="Add test splitting or parallelism to shorten feedback time on release-critical jobs.",
                    phase="Phase C: Scale Optimization",
                    confidence="medium",
                    framework_refs=["DORA"],
                    evidence=line_matches(source, "test")[:2],
                )
            )

    return findings


def jenkins_rules(files: list[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    has_casc = any(f.kind == "jenkins_casc" for f in files)

    for source in [f for f in files if f.kind == "jenkins"]:
        if re.search(r"agent\s+any", source.text):
            findings.append(
                Finding(
                    rule_id="JK001",
                    title="Jenkins pipeline uses broad `agent any`",
                    severity="high",
                    dimension="scalability",
                    summary="Jenkinsfile runs on an unconstrained agent target.",
                    impact="Builds may land on the controller or other unsuitable executors, increasing fragility and risk.",
                    recommendation="Pin execution to isolated build agents and ensure the controller does not run normal workloads.",
                    phase="Phase C: Scale Optimization",
                    confidence="medium",
                    framework_refs=["OWASP CI/CD-SEC-8", "DORA"],
                    evidence=line_matches(source, "agent any")[:1],
                )
            )

        if "withCredentials" in source.text and has_any(source.text, ["prod-creds", "deploy", "passwordVariable"]):
            findings.append(
                Finding(
                    rule_id="JK002",
                    title="Jenkins deploy credentials appear broad and long-lived",
                    severity="critical",
                    dimension="security",
                    summary="Deployment logic uses Jenkins-managed credentials directly in the pipeline.",
                    impact="Long-lived deploy credentials are harder to scope, rotate, and audit than ephemeral auth patterns.",
                    recommendation="Reduce credential scope and move deploy authentication toward short-lived, least-privileged identity flows.",
                    phase="Phase A: Hardening",
                    confidence="medium",
                    framework_refs=["OWASP CI/CD-SEC-6", "SSDF"],
                    evidence=line_matches(source, "withCredentials")[:2],
                )
            )

        if "@Library" not in source.text and has_any(source.text, ["Deploy", "deploy"]):
            findings.append(
                Finding(
                    rule_id="JK003",
                    title="Jenkins pipeline lacks shared library reuse",
                    severity="medium",
                    dimension="maintainability",
                    summary="Deploy logic appears embedded directly in the Jenkinsfile.",
                    impact="Standardizing fixes and rollout patterns across jobs becomes slower and more error-prone.",
                    recommendation="Extract common pipeline stages into a versioned Jenkins Shared Library.",
                    phase="Phase B: Standardization",
                    confidence="medium",
                    framework_refs=["DORA"],
                    evidence=line_matches(source, "stage(")[:3],
                )
            )

        if not has_casc:
            findings.append(
                Finding(
                    rule_id="JK004",
                    title="Jenkins configuration as code is missing",
                    severity="high",
                    dimension="maintainability",
                    summary="No JCasC-style Jenkins configuration file was found alongside the pipeline.",
                    impact="Controller setup may drift in the UI and become hard to reproduce or review.",
                    recommendation="Capture controller configuration in JCasC and version it with the rest of the delivery platform assets.",
                    phase="Phase B: Standardization",
                    confidence="high",
                    framework_refs=["SSDF"],
                    evidence=[Evidence(source.path.as_posix(), None, "Jenkinsfile found without nearby JCasC file.")],
                )
            )

    return findings


def recent_run_rules(recent_runs: RecentRuns | None) -> list[Finding]:
    if recent_runs is None or recent_runs.provider != "gitlab" or not recent_runs.pipelines:
        return []

    findings: list[Finding] = []
    failed_pipelines = [pipeline for pipeline in recent_runs.pipelines if pipeline.status == "failed"]
    if len(failed_pipelines) >= max(2, len(recent_runs.pipelines) // 2):
        evidence = [
            Evidence(
                path=f"gitlab pipeline #{pipeline.pipeline_id}",
                line=None,
                snippet=f"status={pipeline.status}, ref={pipeline.ref}, updated_at={pipeline.updated_at}",
            )
            for pipeline in failed_pipelines[:4]
        ]
        findings.append(
            Finding(
                rule_id="GLR001",
                title="Recent GitLab pipeline history is unstable",
                severity="high",
                dimension="reliability",
                summary="A large share of the most recent GitLab pipelines ended in failure.",
                impact="Teams are likely spending time on broken delivery flow instead of predictable releases.",
                recommendation="Prioritize stabilization of the most common failing jobs before adding more CI scope or deployment complexity.",
                phase="Phase A: Hardening",
                confidence="medium",
                framework_refs=["DORA"],
                evidence=evidence,
            )
        )

    job_failures: dict[str, int] = defaultdict(int)
    queued_jobs: list[tuple[str, float]] = []
    for pipeline in recent_runs.pipelines:
        for job in pipeline.jobs:
            if job.status == "failed":
                job_failures[f"{job.stage}/{job.name}"] += 1
            if job.queued_duration_seconds and job.queued_duration_seconds >= 60:
                queued_jobs.append((f"{job.stage}/{job.name}", job.queued_duration_seconds))

    repeated_failed_jobs = sorted(job_failures.items(), key=lambda item: item[1], reverse=True)
    if repeated_failed_jobs and repeated_failed_jobs[0][1] >= 2:
        evidence = [
            Evidence(
                path="gitlab recent jobs",
                line=None,
                snippet=f"{name} failed {count} times across the fetched pipelines",
            )
            for name, count in repeated_failed_jobs[:4]
        ]
        findings.append(
            Finding(
                rule_id="GLR002",
                title="Recent GitLab runs show repeated failures in the same job",
                severity="medium",
                dimension="reliability",
                summary="The same GitLab job has failed multiple times in the recent run window.",
                impact="Teams may be rerunning pipelines without addressing the underlying bottleneck or flaky step.",
                recommendation="Investigate the most frequently failing job first and add tighter diagnostics or isolation around that stage.",
                phase="Phase A: Hardening",
                confidence="medium",
                framework_refs=["DORA"],
                evidence=evidence,
            )
        )

    if queued_jobs:
        slowest = sorted(queued_jobs, key=lambda item: item[1], reverse=True)[:4]
        evidence = [
            Evidence(
                path="gitlab recent jobs",
                line=None,
                snippet=f"{name} queued for {seconds:.1f}s",
            )
            for name, seconds in slowest
        ]
        findings.append(
            Finding(
                rule_id="GLR003",
                title="Recent GitLab jobs show significant queue time",
                severity="medium",
                dimension="scalability",
                summary="Recent GitLab jobs spent a noticeable amount of time waiting before execution.",
                impact="Runner bottlenecks can stretch feedback loops even when the CI logic itself is acceptable.",
                recommendation="Review runner capacity, tag pinning, and job parallelism to reduce queue delays on the hottest paths.",
                phase="Phase C: Scale Optimization",
                confidence="medium",
                framework_refs=["DORA"],
                evidence=evidence,
            )
        )

    return findings


def positive_strengths(files: list[SourceFile]) -> list[str]:
    strengths: list[str] = []
    all_text = "\n".join(file.text for file in files)

    if "id-token: write" in all_text or "oidc" in all_text.lower():
        strengths.append("OIDC or workload identity signals detected in CI configuration.")
    if "concurrency:" in all_text:
        strengths.append("Concurrency controls are present for at least part of the pipeline estate.")
    if "workflow_call:" in all_text or "@Library" in all_text or "component:" in all_text:
        strengths.append("Some reusable pipeline patterns are already in use.")
    if "environment:" in all_text:
        strengths.append("Environment declarations exist in at least one deployment path.")

    if not strengths:
        strengths.append("The repo has machine-readable CI configuration, which is enough to start a modernization plan.")

    return strengths


def debug_notes(files: list[SourceFile], findings: list[Finding], recent_runs: RecentRuns | None) -> list[str]:
    notes: list[str] = []
    notes.append(f"Detected {len(files)} supported CI file(s): " + ", ".join(f"{file.kind}:{file.path.name}" for file in files))

    for source in files:
        lines = source.lines
        stages = len([line for line in lines if "stage:" in line])
        needs = len([line for line in lines if "needs:" in line])
        envs = len([line for line in lines if "environment:" in line])
        artifacts = len([line for line in lines if "artifacts:" in line])
        scripts = len([line for line in lines if "script:" in line])
        notes.append(
            f"{source.path.name}: scripts={scripts}, stage_refs={stages}, needs_refs={needs}, environment_refs={envs}, artifacts_refs={artifacts}"
        )

        if source.kind == "gitlab":
            if has_any(source.text, ["glpat-", "Authentication Basic", "AllowUnencryptedAuthentication", "curl.exe", "git clone"]):
                notes.append(f"{source.path.name}: detected credential or transport signals in inline script commands.")
            if has_any(source.text, ["Remove-Item -Recurse -Force"]):
                notes.append(f"{source.path.name}: detected destructive recursive cleanup on the runner.")

    if recent_runs is not None:
        notes.append(f"Loaded recent run metadata from {recent_runs.provider} for {recent_runs.project_label} ({recent_runs.fetched_count} pipelines).")
        notes.extend(recent_runs.summary_notes)

    if not findings:
        notes.append("No current rule matched this CI configuration. This does not mean the repo is healthy; it means the ruleset needs expansion for this pattern.")

    return notes


def score_findings(findings: list[Finding]) -> tuple[dict[str, int], int]:
    scores = {dimension: 100 for dimension in WEIGHTS}
    for finding in findings:
        scores[finding.dimension] = max(0, scores[finding.dimension] - finding.points)

    weighted_total = sum(scores[dimension] * weight for dimension, weight in WEIGHTS.items())
    overall = round(weighted_total / sum(WEIGHTS.values()))
    return scores, overall


def analyze(target: Path, files: list[SourceFile], recent_runs: RecentRuns | None = None) -> AnalysisResult:
    findings = []
    findings.extend(github_rules(files))
    findings.extend(gitlab_rules(files))
    findings.extend(circleci_rules(files))
    findings.extend(jenkins_rules(files))
    findings.extend(recent_run_rules(recent_runs))

    findings.sort(key=lambda item: (severity_rank(item.severity), item.dimension, item.title))
    scores, overall = score_findings(findings)
    return AnalysisResult(
        target=target,
        files=files,
        findings=findings,
        scores=scores,
        overall_score=overall,
        strengths=positive_strengths(files),
        debug_notes=debug_notes(files, findings, recent_runs),
        recent_runs=recent_runs,
    )


def severity_rank(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return order[severity]
