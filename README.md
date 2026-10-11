# SupplyGuard

SupplyGuard is a local Streamlit prototype for scanning public GitHub repositories for known vulnerable dependencies. It reads supported dependency files, checks exact package versions against OSV, shows advisory IDs with one CVE link when available, and suggests remediation steps.

## Run on Windows

Use Python 3.10 or later. Open PowerShell in this folder and run:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Streamlit prints a local URL, normally `http://localhost:8501`. To open it from PowerShell:

```powershell
Start-Process 'http://localhost:8501'
```

Keep the PowerShell window running while you use the app. Stop the server with Ctrl+C.

## Scan a repository

1. Enter a public GitHub repository URL in the left sidebar.
2. Optionally enter a branch. If blank, SupplyGuard uses the repository's default branch. A URL ending in `/tree/branch-name` also selects that branch.
3. Select **Scan repository** and wait for the scan summary.
4. Use the sidebar severity, status, and search filters to change the displayed findings. The default is **All severities**; **Clear filters** resets every filter.
5. Open a finding or use **Recommendations** to see the advisory ID, one CVE link when available, suggested target version, affected file, rationale, and validation guidance.
6. Download JSON or CSV from **Reports**.

## Supported inputs

- npm `package-lock.json` and `npm-shrinkwrap.json`, including nested packages in modern lockfiles.
- Python `requirements.txt` entries pinned with `==` or `===`.
- Direct Maven dependencies from `pom.xml`, including local properties and dependency management versions.

Every scan is pinned to the branch's commit SHA returned by GitHub. The scan only reads repository contents; it does not run repository code, modify files, or create a pull request.

## Prototype limits

- Only public GitHub repositories are supported. GitHub's unauthenticated REST API has a limit; the app displays a clear message if it is reached.
- Python transitive dependencies require a generated lockfile, and Maven transitive dependencies require a resolved dependency tree. This prototype does not claim full transitive coverage for those ecosystems.
- Requirements that are not exact `==`/`===` pins are skipped with a warning.
- Scan history and finding statuses are stored in the active Streamlit session. They are not shared across users and may be lost when the browser session is reset.
- Recommendations are reviewable guidance. A person must update the repository and run its tests.

## Main behavior

- The overview shows scan totals as a readable inline summary instead of pale metric cards.
- The overview identifies JavaScript / Node.js, Python, and Java / Maven stacks from supported manifests and recognizable package names.
- Finding tables keep advisory IDs as text and show a single CVE link when one is available.
- Blank, invalid, or stale severity filter state normalizes to `all`.
- Finding severity is canonicalized to `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `UNRATED`.
- Display filters are applied after scanning and after OSV lookups. Summary metrics and exports use all findings.
- OSV `querybatch` results are expanded to full advisory records before severity, fixed-version, aliases, and references are displayed.
- A finding is marked fixed after a later scan no longer reports the same advisory for that repository. Status can also be managed manually.

