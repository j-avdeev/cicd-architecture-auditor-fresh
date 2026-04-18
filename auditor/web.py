from __future__ import annotations

import cgi
import html
import json
import shutil
import subprocess
import tempfile
import threading
import uuid
import zipfile
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from auditor.discovery import discover_ci_files
from auditor.models import ProjectContext, RemediationResult
from auditor.remediation import execute_codex_for_findings, remediation_prompt
from auditor.report import base_script, base_styles, finding_key, report_fragment
from auditor.rules import analyze


ROOT = Path(__file__).resolve().parent.parent
APP_VERSION = "build 2026-04-18b"
JOBS: dict[str, dict[str, object]] = {}
JOB_PROCESSES: dict[str, subprocess.Popen] = {}
JOB_LOCK = threading.Lock()


@dataclass
class RepoInput:
    repo_id: str
    source_type: str = "path"
    target_path: str = ""
    git_url: str = ""
    upload_name: str = ""
    upload: cgi.FieldStorage | None = None
    display_label: str = ""

    @property
    def effective_source_type(self) -> str:
        if self.target_path.strip():
            return "path"
        return self.source_type

    @property
    def remediation_enabled(self) -> bool:
        return self.effective_source_type == "path" and bool(self.target_path.strip())


class AuditorHandler(BaseHTTPRequestHandler):
    server_version = "CICDAuditor/0.3"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/job-status":
            self.handle_job_status(parsed)
            return
        if parsed.path == "/":
            self.respond(self.page())
            return
        self.respond(self.page(error=f"Unknown path: {parsed.path}"), status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/remediation-start-json":
            self.handle_remediation_start_json()
            return
        if parsed.path == "/remediation-stop":
            self.handle_remediation_stop()
            return
        if parsed.path == "/remediation-start":
            self.handle_remediation_start()
            return
        if parsed.path != "/analyze":
            self.respond(self.page(error=f"Unknown path: {parsed.path}"), status=HTTPStatus.NOT_FOUND)
            return

        content_type = self.headers.get_content_type()
        context = ProjectContext()
        repos = [RepoInput(repo_id="0")]

        if content_type == "application/x-www-form-urlencoded":
            params = read_urlencoded_params(self)
            repos = self.repo_inputs_from_params(params)
            context = project_context_from_params(params)
        else:
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                    "CONTENT_LENGTH": self.headers.get("Content-Length", "0"),
                },
            )
            repos = self.repo_inputs_from_form(form)
            context = ProjectContext(
                description=(form.getfirst("project_description") or "").strip(),
                stack=(form.getfirst("project_stack") or "").strip(),
                goals=(form.getfirst("project_goals") or "").strip(),
            )

        try:
            report_html, repos = self.render_report_for_repos(repos, context=context)
            self.respond(self.page(report_html=report_html, context=context, repos=repos))
        except Exception as exc:  # noqa: BLE001
            self.respond(self.page(error=str(exc), context=context, repos=repos), status=HTTPStatus.BAD_REQUEST)

    def repo_inputs_from_params(self, params: dict[str, list[str]]) -> list[RepoInput]:
        repo_ids = self.parse_repo_ids(params.get("repo_ids", [""])[0] if params.get("repo_ids") else "")
        repos: list[RepoInput] = []
        for repo_id in repo_ids:
            repos.append(
                RepoInput(
                    repo_id=repo_id,
                    source_type=(params.get(f"repo_source_type_{repo_id}", ["path"])[0] or "path").strip() or "path",
                    target_path=(params.get(f"target_path_{repo_id}", [""])[0]).strip(),
                    git_url=(params.get(f"git_url_{repo_id}", [""])[0]).strip(),
                    upload_name=(params.get(f"upload_name_{repo_id}", [""])[0]).strip(),
                    display_label=(params.get(f"display_label_{repo_id}", [""])[0]).strip(),
                )
            )
        return repos or [RepoInput(repo_id="0")]

    def repo_inputs_from_form(self, form: cgi.FieldStorage) -> list[RepoInput]:
        repo_ids = self.parse_repo_ids(form.getfirst("repo_ids") or "")
        repos: list[RepoInput] = []
        for repo_id in repo_ids:
            upload_key = f"repo_zip_{repo_id}"
            upload = form[upload_key] if upload_key in form else None
            upload_name = ""
            if upload is not None:
                if isinstance(upload, list):
                    upload = upload[0]
                upload_name = Path(getattr(upload, "filename", "")).name if getattr(upload, "filename", "") else ""
            repos.append(
                RepoInput(
                    repo_id=repo_id,
                    source_type=(form.getfirst(f"repo_source_type_{repo_id}") or "path").strip() or "path",
                    target_path=(form.getfirst(f"target_path_{repo_id}") or "").strip(),
                    git_url=(form.getfirst(f"git_url_{repo_id}") or "").strip(),
                    upload_name=upload_name,
                    upload=upload,
                    display_label=(form.getfirst(f"display_label_{repo_id}") or "").strip(),
                )
            )
        return repos or [RepoInput(repo_id="0")]

    def parse_repo_ids(self, raw: str) -> list[str]:
        ids = [part.strip() for part in raw.split(",") if part.strip()]
        return ids or ["0"]

    def active_repos(self, repos: list[RepoInput]) -> list[RepoInput]:
        active: list[RepoInput] = []
        for repo in repos:
            source_type = repo.effective_source_type
            if source_type == "path" and repo.target_path.strip():
                active.append(repo)
            elif source_type == "git" and repo.git_url.strip():
                active.append(repo)
            elif source_type == "zip" and (repo.upload_name or (repo.upload is not None and getattr(repo.upload, "filename", ""))):
                active.append(repo)
        return active

    def render_report_for_repos(self, repos: list[RepoInput], context: ProjectContext) -> tuple[str, list[RepoInput]]:
        active_repos = self.active_repos(repos)
        if not active_repos:
            raise ValueError("Provide at least one repository source: local path, .zip upload, or git URL.")

        rendered: list[str] = []
        for index, repo in enumerate(active_repos, start=1):
            if repo.effective_source_type == "path":
                label = repo.target_path.strip()
                resolved = Path(label).expanduser().resolve()
                repo.display_label = label
                result = self.analyze_target(resolved)
                fragment = report_fragment(
                    result,
                    context=context,
                    build_label=APP_VERSION,
                    display_target=label,
                    remediation_inputs=self.remediation_inputs_for_repo(repo, active_repos, context),
                    remediation_enabled=repo.remediation_enabled,
                )
            elif repo.effective_source_type == "zip":
                if repo.upload is None or not getattr(repo.upload, "filename", ""):
                    raise ValueError(f"Repo #{index}: upload a .zip archive or switch the source type.")
                fragment, label = self.render_report_for_upload(repo.upload, context=context)
                repo.upload_name = label
                repo.display_label = label
            elif repo.effective_source_type == "git":
                if not repo.git_url.strip():
                    raise ValueError(f"Repo #{index}: enter a git repository URL or switch the source type.")
                fragment, label = self.render_report_for_git(repo.git_url.strip(), context=context)
                repo.display_label = label
            else:
                raise ValueError(f"Repo #{index}: unsupported source type '{repo.effective_source_type}'.")

            rendered.append(
                f"<section class='panel repo-report'><div class='repo-report-head'><span class='repo-chip'>Repo {index}</span><h2>{html.escape(label)}</h2></div>{fragment}</section>"
            )

        return "".join(rendered), repos

    def analyze_target(self, target: Path):
        resolved = target.resolve()
        if not resolved.exists():
            raise ValueError(f"Target path does not exist: {resolved}")
        files = discover_ci_files(resolved)
        if not files:
            raise ValueError(f"No supported CI files found under: {resolved}")
        return analyze(resolved, files)

    def render_report_for_git(self, git_url: str, context: ProjectContext) -> tuple[str, str]:
        with tempfile.TemporaryDirectory(prefix="ci_auditor_git_") as temp_dir:
            clone_dir = Path(temp_dir) / "repo"
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", git_url, str(clone_dir)],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except FileNotFoundError as exc:
                raise ValueError("Git is not installed or not available on PATH for the web server process.") from exc
            except subprocess.CalledProcessError as exc:
                stderr = (exc.stderr or exc.stdout or "").strip()
                raise ValueError(f"Could not clone git repository: {stderr or git_url}") from exc

            result = self.analyze_target(clone_dir)
            fragment = report_fragment(result, context=context, build_label=APP_VERSION, display_target=git_url)
            return fragment, git_url

    def render_report_for_upload(self, upload: cgi.FieldStorage, context: ProjectContext) -> tuple[str, str]:
        filename = Path(upload.filename).name
        if not filename.lower().endswith(".zip"):
            raise ValueError("Uploaded file must be a .zip archive.")

        with tempfile.TemporaryDirectory(prefix="ci_auditor_upload_") as temp_dir:
            archive_path = Path(temp_dir) / filename
            with archive_path.open("wb") as handle:
                shutil.copyfileobj(upload.file, handle)

            extract_dir = Path(temp_dir) / "repo"
            with zipfile.ZipFile(archive_path) as zf:
                zf.extractall(extract_dir)

            candidates = [extract_dir]
            children = [path for path in extract_dir.iterdir() if path.is_dir()]
            if len(children) == 1:
                candidates.insert(0, children[0])

            for candidate in candidates:
                files = discover_ci_files(candidate)
                if files:
                    result = analyze(candidate, files)
                    return report_fragment(result, context=context, build_label=APP_VERSION, display_target=filename), filename

        raise ValueError("No supported CI files were found in the uploaded archive.")

    def remediation_inputs_for_repo(self, primary_repo: RepoInput, active_repos: list[RepoInput], context: ProjectContext) -> str:
        values: list[tuple[str, str]] = [
            ("repo_ids", ",".join(repo.repo_id for repo in active_repos)),
            ("primary_repo_id", primary_repo.repo_id),
            ("project_description", context.description),
            ("project_stack", context.stack),
            ("project_goals", context.goals),
        ]
        for repo in active_repos:
            values.extend(
                [
                    (f"repo_source_type_{repo.repo_id}", repo.source_type),
                    (f"target_path_{repo.repo_id}", repo.target_path),
                    (f"git_url_{repo.repo_id}", repo.git_url),
                    (f"upload_name_{repo.repo_id}", repo.upload_name),
                    (f"display_label_{repo.repo_id}", repo.display_label or repo.target_path or repo.git_url or repo.upload_name),
                ]
            )
        return "".join(
            f"<input type='hidden' name='{html.escape(name)}' value='{html.escape(value, quote=True)}'>"
            for name, value in values
        )

    def handle_job_status(self, parsed) -> None:
        job_id = (parse_qs(parsed.query).get("id", [""])[0]).strip()
        payload = job_payload(job_id)
        if payload is None:
            body = json.dumps({"error": f"Unknown remediation job: {job_id}"}).encode("utf-8")
            self.send_response(HTTPStatus.NOT_FOUND)
        else:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_remediation_start(self) -> None:
        params = read_urlencoded_params(self)
        repos = self.repo_inputs_from_params(params)
        context = project_context_from_params(params)
        try:
            primary_repo, active_repos, findings, prompt_preview = self.prepare_remediation(params, repos, context)
            target = Path(primary_repo.target_path).expanduser().resolve()
            mode = params_mode(params)
            job_id = create_job(target, findings, mode, prompt_preview)
            additional_context = build_additional_repo_context(active_repos, primary_repo)
            start_job_runner(job_id, target, findings, context, additional_context)
            console_panel = render_remediation_job_panel(job_id, primary_repo, active_repos, findings, context, mode, prompt_preview)
            report_html, repos = self.render_report_for_repos(repos, context=context)
            self.respond(self.page(report_html=console_panel + report_html, context=context, repos=repos))
        except Exception as exc:  # noqa: BLE001
            remediation_result = RemediationResult(
                mode=params_mode(params),
                finding_title=f"{len(params.get('selected_finding', []))} findings",
                target_path="",
                command="",
                success=False,
                message=str(exc),
                finding_count=len(params.get("selected_finding", [])),
            )
            self.respond(
                self.page(
                    error=str(exc),
                    report_html=render_remediation_error_panel(remediation_result),
                    context=context,
                    repos=repos,
                ),
                status=HTTPStatus.BAD_REQUEST,
            )

    def handle_remediation_start_json(self) -> None:
        params = read_urlencoded_params(self)
        repos = self.repo_inputs_from_params(params)
        context = project_context_from_params(params)
        try:
            primary_repo, active_repos, findings, prompt_preview = self.prepare_remediation(params, repos, context)
            target = Path(primary_repo.target_path).expanduser().resolve()
            mode = params_mode(params)
            job_id = create_job(target, findings, mode, prompt_preview)
            additional_context = build_additional_repo_context(active_repos, primary_repo)
            start_job_runner(job_id, target, findings, context, additional_context)
            self.respond_json(job_payload(job_id) or {"error": "Failed to create job."})
        except Exception as exc:  # noqa: BLE001
            self.respond_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def handle_remediation_stop(self) -> None:
        params = read_urlencoded_params(self)
        job_id = (params.get("job_id", [""])[0]).strip()
        if not job_id:
            self.respond_json({"error": "Missing job id."}, status=HTTPStatus.BAD_REQUEST)
            return
        process = JOB_PROCESSES.get(job_id)
        if process is None:
            payload = job_payload(job_id)
            if payload is None:
                self.respond_json({"error": f"Unknown remediation job: {job_id}"}, status=HTTPStatus.NOT_FOUND)
                return
            self.respond_json(payload)
            return
        try:
            update_job(job_id, stop_requested=True, message="Stopping Codex...")
            process.terminate()
            append_job_log(job_id, "[auditor] Stop requested.")
            self.respond_json(job_payload(job_id) or {"error": f"Unknown remediation job: {job_id}"})
        except Exception as exc:  # noqa: BLE001
            self.respond_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def prepare_remediation(
        self,
        params: dict[str, list[str]],
        repos: list[RepoInput],
        context: ProjectContext,
    ) -> tuple[RepoInput, list[RepoInput], list, str]:
        active_repos = self.active_repos(repos)
        primary_repo_id = (params.get("primary_repo_id", [""])[0]).strip()
        selected_keys = [item.strip() for item in params.get("selected_finding", []) if item.strip()]
        mode = params_mode(params)

        primary_repo = next((repo for repo in active_repos if repo.repo_id == primary_repo_id), None)
        if primary_repo is None:
            raise ValueError("The selected repository is no longer available. Please re-run the audit and try again.")
        if not primary_repo.remediation_enabled:
            raise ValueError("Codex remediation currently requires the primary repository to be analyzed from a local path.")
        if not selected_keys:
            raise ValueError("Select at least one finding before starting Codex remediation.")

        target = Path(primary_repo.target_path).expanduser().resolve()
        analyzed = self.analyze_target(target)
        findings_by_key = {finding_key(item): item for item in analyzed.findings}
        selected_findings = [findings_by_key[key] for key in selected_keys if key in findings_by_key]
        if not selected_findings:
            raise ValueError("The selected findings are no longer present. Please re-run the audit and try again.")

        additional_context = build_additional_repo_context(active_repos, primary_repo)
        prompt_preview = remediation_prompt(selected_findings, target, context, mode, additional_context=additional_context)
        return primary_repo, active_repos, selected_findings, prompt_preview

    def page(
        self,
        report_html: str = "",
        error: str = "",
        context: ProjectContext | None = None,
        repos: list[RepoInput] | None = None,
    ) -> str:
        context = context or ProjectContext()
        repos = repos or [RepoInput(repo_id="0")]
        report_section = ""
        if error:
            report_section = f"<section class='panel error'><h2>Analysis Error</h2><p>{html.escape(error)}</p></section>"
        if report_html:
            report_section += report_html

        repo_cards = "".join(self.render_repo_card(repo, index, len(repos)) for index, repo in enumerate(repos))
        repo_ids = ",".join(repo.repo_id for repo in repos)
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CI/CD Architecture Auditor</title>
  {base_styles()}
  <style>
    .app-shell {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 28px 20px 56px;
    }}
    .intro {{
      display: grid;
      grid-template-columns: 1.25fr .9fr;
      gap: 18px;
      align-items: stretch;
    }}
    .eyebrow {{
      letter-spacing: .16em;
      text-transform: uppercase;
      font-size: 12px;
      color: var(--accent);
      margin-bottom: 14px;
    }}
    .headline {{
      font-size: clamp(2.2rem, 3.7vw, 4rem);
      line-height: .94;
      margin-bottom: 14px;
    }}
    .lead {{
      font-size: 1.05rem;
      color: var(--muted);
      max-width: 52ch;
    }}
    .form-stack {{
      display: grid;
      gap: 12px;
    }}
    .repo-stack {{
      display: grid;
      gap: 14px;
    }}
    .repo-card {{
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 18px;
      background: linear-gradient(180deg, rgba(255,255,255,.96), rgba(248,246,241,.96));
      display: grid;
      gap: 14px;
    }}
    .repo-card-head {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
    }}
    .repo-title {{
      font-size: 1rem;
      font-weight: bold;
    }}
    .source-switch {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
    }}
    .source-switch label {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-weight: 600;
      background: #fff;
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 9px 12px;
    }}
    .source-panel {{
      display: none;
      gap: 10px;
    }}
    .source-panel.active {{
      display: grid;
    }}
    .repo-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }}
    .settings-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      margin-top: 8px;
    }}
    .linklike {{
      display: inline-flex;
      align-items: center;
      text-decoration: none;
    }}
    .muted-inline {{
      color: var(--muted);
      font-size: .92rem;
      margin: 0;
    }}
    .repo-report {{
      margin-top: 18px;
    }}
    .repo-report-head {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      margin-bottom: 14px;
    }}
    .repo-chip {{
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 6px 10px;
      background: #ece6da;
      color: var(--ink);
      font-size: .86rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .08em;
    }}
    label {{
      font-weight: bold;
      font-size: .95rem;
    }}
    input[type="text"], input[type="url"], input[type="file"], textarea {{
      width: 100%;
      box-sizing: border-box;
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px 14px;
      font: inherit;
      background: #fff;
    }}
    textarea {{
      min-height: 110px;
      resize: vertical;
    }}
    .build-callout {{
      display: inline-block;
      margin-top: 10px;
      color: var(--muted);
      font-size: .92rem;
    }}
    button {{
      border: 0;
      border-radius: 999px;
      padding: 12px 16px;
      font: inherit;
      cursor: pointer;
      transition: transform .16s ease, box-shadow .16s ease, background .16s ease;
    }}
    .cta {{
      background: #0f766e;
      color: #fff;
      box-shadow: 0 10px 20px rgba(15,118,110,.18);
    }}
    .secondary {{
      background: #ece6da;
      color: var(--ink);
    }}
    button:hover {{
      transform: translateY(-1px);
    }}
    .facts {{
      display: grid;
      gap: 12px;
    }}
    .fact {{
      border-top: 1px solid var(--border);
      padding-top: 12px;
    }}
    .error {{
      border-color: #ef4444;
      background: #fff7f7;
    }}
    .warning-note {{
      border-color: #d97706;
      background: #fff8eb;
    }}
    .report-shell {{
      padding-left: 0;
      padding-right: 0;
    }}
    @media (max-width: 860px) {{
      .intro {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <main class="app-shell">
    <section class="hero intro">
      <div>
        <div class="eyebrow">Hackathon MVP</div>
        <h1 class="headline">CI/CD Architecture Auditor MVP</h1>
        <p class="lead">Analyze one or more repositories and send findings to Codex with shared multi-repo context.</p>
        <p class="build-callout">Analyzer version: <strong>{html.escape(APP_VERSION)}</strong></p>
      </div>
      <div class="panel facts">
        <div class="fact">
          <strong>What it reads</strong>
          <p class="muted">GitHub Actions, GitLab CI, Jenkinsfiles, and CircleCI config.</p>
        </div>
        <div class="fact">
          <strong>Codex remediation</strong>
          <p class="muted">`Fix with Codex` works for repos analyzed from a local path and includes the other selected repos in the prompt context.</p>
        </div>
      </div>
    </section>

    <section class="panel">
      <h2>Analyze</h2>
      <form class="form-stack" method="post" action="/analyze" enctype="multipart/form-data">
        <input id="repo_ids" type="hidden" name="repo_ids" value="{html.escape(repo_ids)}">
        <div id="repo-list" class="repo-stack">
          {repo_cards}
        </div>
        <div class="repo-actions">
          <button id="add-repo" class="secondary" type="button">Add One More Repo</button>
          <button class="cta" type="submit">Analyze</button>
          <a class="linklike" href="/"><button class="secondary" type="button">Reset</button></a>
        </div>
        <div class="settings-actions">
          <button id="import-settings" class="secondary" type="button">Import Settings</button>
          <button id="export-settings" class="secondary" type="button">Export Filled Settings</button>
          <input id="settings-file" type="file" accept=".json,application/json" hidden>
          <p class="muted-inline">Local path and git settings restore fully. Zip uploads cannot be reattached from an imported file.</p>
        </div>
        <label for="project_description">What is this project?</label>
        <textarea id="project_description" name="project_description" placeholder="Desktop simulation product, legacy Windows app, internal tooling, monorepo, etc.">{html.escape(context.description)}</textarea>
        <label for="project_stack">Stack / delivery stack</label>
        <textarea id="project_stack" name="project_stack" placeholder="GitLab CI, Nexus, Windows runners, PowerShell, Python, Qt, Jenkins, Docker, Kubernetes, etc.">{html.escape(context.stack)}</textarea>
        <label for="project_goals">What do you want from the auditor?</label>
        <textarea id="project_goals" name="project_goals" placeholder="Harden GitLab pipeline, remove brittle runner paths, improve reliability, reduce manual steps, etc.">{html.escape(context.goals)}</textarea>
      </form>
    </section>

    <section class="panel console-panel" data-global-remediation hidden>
      <h2>General Codex Log</h2>
      <div class="console-meta">
        <span class="status-pill" data-global-job-field="status">idle</span>
        <span><strong>Mode:</strong> <span data-global-job-field="mode"></span></span>
        <span><strong>Finding:</strong> <span data-global-job-field="finding_title"></span></span>
        <span><strong>Repo:</strong> <span data-global-job-field="target_path"></span></span>
      </div>
      <p data-global-job-field="message">Waiting for Codex to start.</p>
      <pre class="console-log" data-global-job-field="logs"></pre>
    </section>

    <section class="panel warning-note">
      <h2>MVP Guardrail</h2>
      <p>A score of 100/100 with 0 findings means only that the current rule set did not match anything in the detected CI files. It is not a proof that the pipeline is clean.</p>
      <p>If you do not see the analyzer version badge or the Discovery Debug section in the report, you are looking at an older server process and should restart the app.</p>
    </section>

    {report_section}
  </main>
</body>
{base_script()}
<script>
  (() => {{
    const repoList = document.getElementById("repo-list");
    const repoIdsInput = document.getElementById("repo_ids");
    const addRepoButton = document.getElementById("add-repo");
    const importSettingsButton = document.getElementById("import-settings");
    const exportSettingsButton = document.getElementById("export-settings");
    const settingsFileInput = document.getElementById("settings-file");

    if (!repoList || !repoIdsInput || !addRepoButton || !importSettingsButton || !exportSettingsButton || !settingsFileInput) {{
      return;
    }}

    const syncRepoIds = () => {{
      const ids = Array.from(repoList.querySelectorAll(".repo-card"))
        .map((card) => card.dataset.repoId)
        .filter(Boolean);
      repoIdsInput.value = ids.join(",");
    }};

    const refreshRemoveButtons = () => {{
      const cards = Array.from(repoList.querySelectorAll(".repo-card"));
      for (const card of cards) {{
        const button = card.querySelector(".remove-repo");
        if (button) {{
          button.hidden = cards.length <= 1;
        }}
      }}
    }};

    const refreshPanels = (card) => {{
      const radios = Array.from(card.querySelectorAll('input[type="radio"][name^="repo_source_type_"]'));
      const checked = radios.find((radio) => radio.checked);
      const selected = checked ? checked.value : "path";
      for (const panel of card.querySelectorAll(".source-panel")) {{
        panel.classList.toggle("active", panel.dataset.sourcePanel === selected);
      }}
    }};

    const wireRepoCard = (card) => {{
      for (const radio of card.querySelectorAll('input[type="radio"][name^="repo_source_type_"]')) {{
        radio.addEventListener("change", () => refreshPanels(card));
      }}
      const removeButton = card.querySelector(".remove-repo");
      if (removeButton) {{
        removeButton.addEventListener("click", () => {{
          card.remove();
          syncRepoIds();
          refreshRemoveButtons();
        }});
      }}
      refreshPanels(card);
    }};

    const createRepoCard = (repoId, indexLabel) => {{
      const card = document.createElement("section");
      card.className = "repo-card";
      card.dataset.repoId = repoId;
      card.innerHTML = {self.js_string_literal(self.repo_card_markup(RepoInput(repo_id="__ID__"), "__INDEX__", 2)).replace("__ID__", "${repoId}").replace("__INDEX__", "${indexLabel}")};
      return card;
    }};

    const refreshRepoTitles = () => {{
      Array.from(repoList.querySelectorAll(".repo-card")).forEach((card, index) => {{
        const title = card.querySelector(".repo-title");
        if (title) {{
          title.textContent = `Repository ${{index + 1}}`;
        }}
      }});
    }};

    const setRepoSource = (card, sourceType) => {{
      const radio = card.querySelector(`input[type="radio"][value="${{sourceType}}"]`);
      if (radio) {{
        radio.checked = true;
      }}
      refreshPanels(card);
    }};

    const populateRepoCard = (card, repo) => {{
      const repoId = card.dataset.repoId;
      const pathInput = card.querySelector(`#target_path_${{repoId}}`);
      const gitInput = card.querySelector(`#git_url_${{repoId}}`);
      const displayInput = card.querySelector(`input[name="display_label_${{repoId}}"]`);
      if (pathInput) {{
        pathInput.value = repo.target_path || "";
      }}
      if (gitInput) {{
        gitInput.value = repo.git_url || "";
      }}
      if (displayInput) {{
        displayInput.value = repo.display_label || repo.target_path || repo.git_url || "";
      }}
      setRepoSource(card, repo.source_type || "path");
    }};

    const currentSettings = () => {{
      const repos = Array.from(repoList.querySelectorAll(".repo-card")).map((card) => {{
        const repoId = card.dataset.repoId;
        const checked = card.querySelector(`input[type="radio"][name="repo_source_type_${{repoId}}"]:checked`);
        const displayInput = card.querySelector(`input[name="display_label_${{repoId}}"]`);
        const pathInput = card.querySelector(`#target_path_${{repoId}}`);
        const gitInput = card.querySelector(`#git_url_${{repoId}}`);
        return {{
          repo_id: repoId,
          source_type: checked ? checked.value : "path",
          target_path: pathInput ? pathInput.value : "",
          git_url: gitInput ? gitInput.value : "",
          display_label: displayInput ? displayInput.value : "",
        }};
      }});
      return {{
        version: 1,
        exported_at: new Date().toISOString(),
        repos,
        project_context: {{
          description: document.getElementById("project_description")?.value || "",
          stack: document.getElementById("project_stack")?.value || "",
          goals: document.getElementById("project_goals")?.value || "",
        }},
      }};
    }};

    const applySettings = (settings) => {{
      const repos = Array.isArray(settings?.repos) && settings.repos.length ? settings.repos : [{{ repo_id: "0", source_type: "path", target_path: "", git_url: "", display_label: "" }}];
      repoList.innerHTML = "";
      for (const [index, repo] of repos.entries()) {{
        const repoId = String(repo.repo_id || Date.now() + index);
        const card = createRepoCard(repoId, index + 1);
        repoList.appendChild(card);
        wireRepoCard(card);
        populateRepoCard(card, {{ ...repo, repo_id: repoId }});
      }}
      document.getElementById("project_description").value = settings?.project_context?.description || "";
      document.getElementById("project_stack").value = settings?.project_context?.stack || "";
      document.getElementById("project_goals").value = settings?.project_context?.goals || "";
      refreshRepoTitles();
      syncRepoIds();
      refreshRemoveButtons();
    }};

    for (const card of repoList.querySelectorAll(".repo-card")) {{
      wireRepoCard(card);
    }}

    refreshRepoTitles();
    refreshRemoveButtons();
    syncRepoIds();

    addRepoButton.addEventListener("click", () => {{
      const nextId = String(Date.now());
      const card = createRepoCard(nextId, repoList.children.length + 1);
      repoList.appendChild(card);
      wireRepoCard(card);
      refreshRepoTitles();
      syncRepoIds();
      refreshRemoveButtons();
    }});

    exportSettingsButton.addEventListener("click", () => {{
      const payload = JSON.stringify(currentSettings(), null, 2);
      const blob = new Blob([payload], {{ type: "application/json" }});
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "auditor-settings.json";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    }});

    importSettingsButton.addEventListener("click", () => {{
      settingsFileInput.value = "";
      settingsFileInput.click();
    }});

    settingsFileInput.addEventListener("change", async () => {{
      const file = settingsFileInput.files && settingsFileInput.files[0];
      if (!file) {{
        return;
      }}
      try {{
        const text = await file.text();
        const settings = JSON.parse(text);
        applySettings(settings);
      }} catch (error) {{
        window.alert("Could not import settings JSON.");
      }}
    }});
  }})();
</script>
</html>
"""

    def render_repo_card(self, repo: RepoInput, index: int, total: int) -> str:
        return f"<section class='repo-card' data-repo-id='{html.escape(repo.repo_id)}'>{self.repo_card_markup(repo, str(index + 1), total)}</section>"

    def repo_card_markup(self, repo: RepoInput, title_number: str, total: int) -> str:
        repo_id = html.escape(repo.repo_id)
        path_checked = "checked" if repo.effective_source_type == "path" else ""
        zip_checked = "checked" if repo.effective_source_type == "zip" else ""
        git_checked = "checked" if repo.effective_source_type == "git" else ""
        upload_note = f"<p class='muted-inline'>Selected zip: {html.escape(repo.upload_name)}</p>" if repo.upload_name else ""
        remove_hidden = "hidden" if total <= 1 else ""
        display_hidden = html.escape(repo.display_label, quote=True)
        return f"""
<input type="hidden" name="display_label_{repo_id}" value="{display_hidden}">
<div class="repo-card-head">
  <div class="repo-title">Repository {html.escape(title_number)}</div>
  <button class="secondary remove-repo" type="button" {remove_hidden}>Remove Repo</button>
</div>
<div class="source-switch">
  <label><input type="radio" name="repo_source_type_{repo_id}" value="path" {path_checked}> Local Path</label>
  <label><input type="radio" name="repo_source_type_{repo_id}" value="zip" {zip_checked}> Zip Upload</label>
  <label><input type="radio" name="repo_source_type_{repo_id}" value="git" {git_checked}> Git Source</label>
</div>
<div class="source-panel" data-source-panel="path">
  <label for="target_path_{repo_id}">Local repository path</label>
  <input id="target_path_{repo_id}" type="text" name="target_path_{repo_id}" value="{html.escape(repo.target_path)}" placeholder="C:\\repos\\my-service">
  <p class="muted-inline">If this path is filled in, Analyze will use it for this repo card and Codex actions can target it later.</p>
</div>
<div class="source-panel" data-source-panel="zip">
  <label for="repo_zip_{repo_id}">Upload zipped repo</label>
  <input id="repo_zip_{repo_id}" type="file" name="repo_zip_{repo_id}" accept=".zip">
  {upload_note}
</div>
<div class="source-panel" data-source-panel="git">
  <label for="git_url_{repo_id}">Git repository URL</label>
  <input id="git_url_{repo_id}" type="url" name="git_url_{repo_id}" value="{html.escape(repo.git_url)}" placeholder="https://github.com/org/repo.git">
</div>
"""

    def js_string_literal(self, value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${")
        return f"`{escaped}`"

    def respond(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def respond_json(self, payload: dict[str, object], status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), AuditorHandler)
    print(f"Serving CI/CD Architecture Auditor {APP_VERSION} on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def read_urlencoded_params(handler: AuditorHandler) -> dict[str, list[str]]:
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length).decode("utf-8", errors="replace")
    return parse_qs(raw)


def project_context_from_params(params: dict[str, list[str]]) -> ProjectContext:
    return ProjectContext(
        description=(params.get("project_description", [""])[0]).strip(),
        stack=(params.get("project_stack", [""])[0]).strip(),
        goals=(params.get("project_goals", [""])[0]).strip(),
    )


def params_mode(params: dict[str, list[str]]) -> str:
    return (params.get("mode", ["plan"])[0]).strip().lower() or "plan"


def build_additional_repo_context(active_repos: list[RepoInput], primary_repo: RepoInput) -> str:
    lines: list[str] = []
    for repo in active_repos:
        if repo.repo_id == primary_repo.repo_id:
            continue
        label = repo.display_label or repo.target_path or repo.git_url or repo.upload_name or f"Repo {repo.repo_id}"
        if repo.effective_source_type == "path" and repo.target_path.strip():
            path = Path(repo.target_path).expanduser().resolve()
            lines.append(f"- {label} (local path: {path})")
            if path.exists():
                try:
                    analyzed = analyze(path, discover_ci_files(path))
                    summary = ", ".join(item.title for item in analyzed.findings[:3]) or "No findings detected"
                    lines.append(f"  Overall score: {analyzed.overall_score}/100. Top findings: {summary}.")
                except Exception as exc:  # noqa: BLE001
                    lines.append(f"  Could not re-analyze this related repo: {exc}")
        elif repo.effective_source_type == "git" and repo.git_url.strip():
            lines.append(f"- {label} (git source only: {repo.git_url})")
        elif repo.effective_source_type == "zip":
            lines.append(f"- {label} (zip upload only; useful as context but not editable by Codex in this run)")
    return "\n".join(lines)


def create_job(target: Path, findings, mode: str, prompt_preview: str) -> str:
    job_id = uuid.uuid4().hex[:10]
    title = findings[0].title if len(findings) == 1 else f"{len(findings)} findings"
    with JOB_LOCK:
        JOBS[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "mode": mode,
            "target_path": str(target),
            "finding_title": title,
            "finding_count": len(findings),
            "prompt_preview": prompt_preview,
            "logs": "[auditor] Job queued.\n",
            "last_message": "",
            "message": "Waiting for Codex to start.",
            "success": None,
            "command": "",
            "stop_requested": False,
        }
    return job_id


def append_job_log(job_id: str, message: str) -> None:
    with JOB_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return
        current = str(job.get("logs", ""))
        line = message.rstrip()
        if not line:
            return
        job["logs"] = (current + line + "\n")[-20000:]


def update_job(job_id: str, **values) -> None:
    with JOB_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return
        job.update(values)


def job_payload(job_id: str) -> dict[str, object] | None:
    with JOB_LOCK:
        job = JOBS.get(job_id)
        if job is None:
            return None
        payload = dict(job)
        payload.pop("stop_requested", None)
        return payload


def start_job_runner(job_id: str, target: Path, findings, context: ProjectContext, additional_context: str) -> None:
    def runner() -> None:
        job = job_payload(job_id)
        if job is None:
            return
        mode = str(job["mode"])
        update_job(job_id, status="running", message="Codex is running.")
        append_job_log(job_id, "[auditor] Job started.")
        try:
            result = execute_codex_for_findings(
                target,
                findings,
                context,
                mode,
                additional_context=additional_context,
                on_log=lambda line: append_job_log(job_id, line),
                on_process_start=lambda process: JOB_PROCESSES.__setitem__(job_id, process),
            )
            stop_requested = bool(JOBS.get(job_id, {}).get("stop_requested"))
            update_job(
                job_id,
                status="stopped" if stop_requested else ("completed" if result.success else "failed"),
                message="Codex stopped by user." if stop_requested else result.message,
                success=False if stop_requested else result.success,
                last_message=result.last_message,
                command=result.command,
            )
        except Exception as exc:  # noqa: BLE001
            append_job_log(job_id, f"[auditor] {exc}")
            update_job(job_id, status="failed", message=str(exc), success=False)
        finally:
            JOB_PROCESSES.pop(job_id, None)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()


def render_remediation_review_panel(primary_repo: RepoInput, active_repos: list[RepoInput], findings, context: ProjectContext, mode: str, prompt_preview: str) -> str:
    hidden = remediation_hidden_inputs_for_page(primary_repo, active_repos, findings, context, mode)
    button_label = "Approve and start Fix with Codex" if mode == "apply" else "Start Plan with Codex"
    note = (
        "<p class='approval-note'>Approval required before Codex is allowed to modify files in this repository.</p>"
        if mode == "apply"
        else "<p class='muted'>This run is read-only and will ask Codex for a remediation plan.</p>"
    )
    return f"""
    <section class="panel review-panel" data-remediation-focus="review">
      <h2>Remediation Review</h2>
      <p><strong>Mode:</strong> {html.escape(mode)} | <strong>Repo:</strong> {html.escape(primary_repo.display_label or primary_repo.target_path)}</p>
      <p><strong>Selected findings:</strong> {len(findings)}</p>
      {note}
      <div class="console-meta">
        <form method="post" action="/remediation-start">
          {hidden}
          <button class="action-button{' apply' if mode == 'apply' else ''}" type="submit">{html.escape(button_label)}</button>
        </form>
      </div>
      <h3>Prompt Preview</h3>
      <pre>{html.escape(prompt_preview)}</pre>
    </section>
"""


def render_remediation_job_panel(job_id: str, primary_repo: RepoInput, active_repos: list[RepoInput], findings, context: ProjectContext, mode: str, prompt_preview: str) -> str:
    title = findings[0].title if len(findings) == 1 else f"{len(findings)} findings"
    return f"""
    <section class="panel console-panel" data-remediation-job="{html.escape(job_id)}" data-remediation-focus="console">
      <h2>Job Console</h2>
      <div class="console-meta">
        <span class="status-pill" data-job-field="status">queued</span>
        <span><strong>Mode:</strong> {html.escape(mode)}</span>
        <span><strong>Target:</strong> {html.escape(title)}</span>
        <span><strong>Repo:</strong> {html.escape(primary_repo.display_label or primary_repo.target_path)}</span>
      </div>
      <p data-job-field="message">Waiting for Codex to start.</p>
      <p class="muted"><strong>Last Codex summary:</strong> <span data-job-field="last_message"></span></p>
      <h3>Prompt Preview</h3>
      <pre>{html.escape(prompt_preview)}</pre>
      <h3>Console Output</h3>
      <pre data-job-field="logs">[auditor] Job queued.</pre>
    </section>
"""


def remediation_hidden_inputs_for_page(primary_repo: RepoInput, active_repos: list[RepoInput], findings, context: ProjectContext, mode: str) -> str:
    values = [
        ("repo_ids", ",".join(repo.repo_id for repo in active_repos)),
        ("primary_repo_id", primary_repo.repo_id),
        ("mode", mode),
        ("project_description", context.description),
        ("project_stack", context.stack),
        ("project_goals", context.goals),
    ]
    for repo in active_repos:
        values.extend(
            [
                (f"repo_source_type_{repo.repo_id}", repo.source_type),
                (f"target_path_{repo.repo_id}", repo.target_path),
                (f"git_url_{repo.repo_id}", repo.git_url),
                (f"upload_name_{repo.repo_id}", repo.upload_name),
                (f"display_label_{repo.repo_id}", repo.display_label or repo.target_path or repo.git_url or repo.upload_name),
            ]
        )
    inputs = [
        f"<input type='hidden' name='{html.escape(name)}' value='{html.escape(value, quote=True)}'>"
        for name, value in values
    ]
    inputs.extend(
        f"<input type='hidden' name='selected_finding' value='{html.escape(finding_key(finding), quote=True)}'>"
        for finding in findings
    )
    return "".join(inputs)


def render_remediation_error_panel(remediation_result: RemediationResult) -> str:
    summary = html.escape(remediation_result.last_message or remediation_result.message)
    output = f"<pre>{html.escape(remediation_result.raw_output)}</pre>" if remediation_result.raw_output else ""
    return f"""
    <section class="panel" data-remediation-focus="error">
      <h2>Codex Remediation</h2>
      <p><strong>Mode:</strong> {html.escape(remediation_result.mode)} | <strong>Finding:</strong> {html.escape(remediation_result.finding_title)}</p>
      <p><strong>Repo:</strong> {html.escape(remediation_result.target_path)}</p>
      <p>{summary}</p>
      {output}
    </section>
"""
