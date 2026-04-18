from __future__ import annotations

import json
from collections import Counter
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

from auditor.models import GitLabConnection, GitLabJobRun, GitLabPipelineRun, RecentRuns


def fetch_gitlab_recent_runs(connection: GitLabConnection) -> RecentRuns:
    project_id = resolve_project_id(connection)
    pipelines_payload = gitlab_get_json(
        connection,
        f"/api/v4/projects/{project_id}/pipelines?per_page={connection.pipeline_limit}" + (f"&ref={quote(connection.ref)}" if connection.ref else ""),
    )

    pipelines: list[GitLabPipelineRun] = []
    for item in pipelines_payload[: connection.pipeline_limit]:
        pipeline_id = int(item["id"])
        pipeline_detail = gitlab_get_json(connection, f"/api/v4/projects/{project_id}/pipelines/{pipeline_id}")
        jobs_payload = gitlab_get_json(connection, f"/api/v4/projects/{project_id}/pipelines/{pipeline_id}/jobs")
        jobs = [
            GitLabJobRun(
                name=str(job.get("name", "")),
                stage=str(job.get("stage", "")),
                status=str(job.get("status", "")),
                duration_seconds=optional_float(job.get("duration")),
                queued_duration_seconds=optional_float(job.get("queued_duration")),
                web_url=str(job.get("web_url", "")),
            )
            for job in jobs_payload
        ]
        pipelines.append(
            GitLabPipelineRun(
                pipeline_id=pipeline_id,
                status=str(pipeline_detail.get("status", item.get("status", ""))),
                ref=str(pipeline_detail.get("ref", item.get("ref", ""))),
                sha=str(pipeline_detail.get("sha", item.get("sha", ""))),
                created_at=str(pipeline_detail.get("created_at", item.get("created_at", ""))),
                updated_at=str(pipeline_detail.get("updated_at", item.get("updated_at", ""))),
                web_url=str(pipeline_detail.get("web_url", item.get("web_url", ""))),
                duration_seconds=optional_float(pipeline_detail.get("duration")),
                jobs=jobs,
            )
        )

    return RecentRuns(
        provider="gitlab",
        project_label=connection.project,
        fetched_count=len(pipelines),
        pipelines=pipelines,
        summary_notes=summarize_runs(pipelines),
    )


def summarize_runs(pipelines: list[GitLabPipelineRun]) -> list[str]:
    notes: list[str] = []
    if not pipelines:
        return ["No recent GitLab pipelines were returned by the API."]

    statuses = Counter(p.status for p in pipelines)
    notes.append("Recent pipeline statuses: " + ", ".join(f"{status}={count}" for status, count in statuses.items()))

    durations = [p.duration_seconds for p in pipelines if p.duration_seconds is not None]
    if durations:
        avg = sum(durations) / len(durations)
        notes.append(f"Average pipeline duration across fetched runs: {avg:.1f}s")

    failing_jobs = Counter()
    for pipeline in pipelines:
        for job in pipeline.jobs:
            if job.status == "failed":
                failing_jobs[f"{job.stage}/{job.name}"] += 1
    if failing_jobs:
        top_name, top_count = failing_jobs.most_common(1)[0]
        notes.append(f"Most repeated failed job in recent runs: {top_name} ({top_count} failures)")

    return notes


def resolve_project_id(connection: GitLabConnection) -> str:
    if connection.project.isdigit():
        return connection.project
    encoded = quote(connection.project, safe="")
    project = gitlab_get_json(connection, f"/api/v4/projects/{encoded}")
    return str(project["id"])


def gitlab_get_json(connection: GitLabConnection, path: str) -> Any:
    base = connection.base_url.rstrip("/")
    request = Request(
        base + path,
        headers={
            "PRIVATE-TOKEN": connection.token,
            "User-Agent": "cicd-architecture-auditor",
        },
    )
    with urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def optional_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
