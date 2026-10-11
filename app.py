from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from functools import cmp_to_key
from typing import Any
from urllib.parse import quote, unquote, urlparse

import requests
import streamlit as st
from cvss import CVSS2, CVSS3, CVSS4
from defusedxml import ElementTree as SafeET
from packaging.version import InvalidVersion, Version


APP_TITLE = "SupplyGuard"
GITHUB_API = "https://api.github.com"
OSV_API = "https://api.osv.dev/v1/querybatch"
OSV_VULN_API = "https://api.osv.dev/v1/vulns"
REQUEST_TIMEOUT = (8, 35)
MAX_MANIFESTS = 120
MAX_FILE_BYTES = 1_000_000
SEVERITY_FILTERS = ("all", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNRATED")
STATUS_FILTERS = ("all", "open", "fixed", "dismissed")
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNRATED": 4}
GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2026-03-10",
    "User-Agent": "SupplyGuard-local-dependency-scanner",
}
JSON_HEADERS = {"Accept": "application/json", "User-Agent": "SupplyGuard-local-dependency-scanner"}


class SupplyGuardError(Exception):
    """An expected, user-facing scan error."""


def normalize_severity_filter(value: Any) -> str:
    """Canonicalize saved/widget state. An invalid filter always means All."""
    if not isinstance(value, str):
        return "all"
    normalized = value.strip().upper()
    if normalized in {"", "ALL"}:
        return "all"
    return normalized if normalized in SEVERITY_FILTERS[1:] else "all"


def normalize_status_filter(value: Any) -> str:
    if not isinstance(value, str):
        return "all"
    normalized = value.strip().lower()
    return normalized if normalized in STATUS_FILTERS else "all"


def normalize_finding_severity(value: Any) -> str:
    """Return one of the supported display severities; unknown data is UNRATED."""
    if value is None:
        return "UNRATED"
    if isinstance(value, (int, float)):
        score = float(value)
        if score >= 9:
            return "CRITICAL"
        if score >= 7:
            return "HIGH"
        if score >= 4:
            return "MEDIUM"
        return "LOW" if score > 0 else "UNRATED"

    normalized = str(value).strip().upper()
    aliases = {
        "MODERATE": "MEDIUM",
        "IMPORTANT": "HIGH",
        "SEVERE": "HIGH",
        "UNKNOWN": "UNRATED",
        "NONE": "UNRATED",
        "N/A": "UNRATED",
        "": "UNRATED",
    }
    normalized = aliases.get(normalized, normalized)
    if re.fullmatch(r"\d+(?:\.\d+)?", normalized):
        return normalize_finding_severity(float(normalized))
    return normalized if normalized in SEVERITY_FILTERS[1:] else "UNRATED"


def clear_finding_filters() -> None:
    # Streamlit invokes this callback before rebuilding the widgets.
    st.session_state["severity_filter"] = "all"
    st.session_state["status_filter"] = "all"
    st.session_state["finding_search"] = ""


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def child_text(element: Any, wanted: str) -> str:
    for child in list(element):
        if local_name(child.tag) == wanted and child.text:
            return child.text.strip()
    return ""


def normalize_package_name(name: str, ecosystem: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.strip().lower()


def github_request_json(url: str) -> dict[str, Any]:
    try:
        response = requests.get(url, headers=GITHUB_HEADERS, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise SupplyGuardError(f"Could not reach GitHub: {exc}") from exc

    if response.status_code == 403 and response.headers.get("X-RateLimit-Remaining") == "0":
        raise SupplyGuardError(
            "GitHub's unauthenticated API limit has been reached. Wait for it to reset, "
            "then scan again. This prototype scans public repositories without a token."
        )
    if response.status_code == 404:
        raise SupplyGuardError("GitHub could not find that repository, branch, or commit.")
    if not response.ok:
        message = ""
        try:
            message = response.json().get("message", "")
        except (ValueError, AttributeError):
            pass
        raise SupplyGuardError(f"GitHub returned HTTP {response.status_code}. {message}".strip())
    try:
        return response.json()
    except ValueError as exc:
        raise SupplyGuardError("GitHub returned data that was not valid JSON.") from exc


def parse_github_url(raw_url: str) -> tuple[str, str, str]:
    raw_url = (raw_url or "").strip()
    if not raw_url:
        raise SupplyGuardError("Enter a public GitHub repository URL.")
    normalized_url = raw_url if "://" in raw_url else f"https://{raw_url}"
    parsed = urlparse(normalized_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"github.com", "www.github.com"}:
        raise SupplyGuardError("Use a repository URL hosted on github.com.")

    parts = [unquote(part) for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        raise SupplyGuardError("Use a URL in the form https://github.com/owner/repository.")
    owner, repo = parts[0], parts[1].removesuffix(".git")
    embedded_branch = ""
    if len(parts) >= 4 and parts[2] in {"tree", "blob"}:
        embedded_branch = "/".join(parts[3:])
    return owner, repo, embedded_branch


def raw_file_url(owner: str, repo: str, commit_sha: str, path: str) -> str:
    encoded_path = quote(path, safe="/@")
    return f"https://raw.githubusercontent.com/{quote(owner)}/{quote(repo)}/{commit_sha}/{encoded_path}"


def fetch_raw_file(owner: str, repo: str, commit_sha: str, path: str) -> tuple[str, str | None, str | None]:
    try:
        response = requests.get(raw_file_url(owner, repo, commit_sha, path), timeout=REQUEST_TIMEOUT)
        if response.status_code == 404:
            return path, None, "file was not found at the selected commit"
        response.raise_for_status()
        return path, response.text, None
    except requests.RequestException as exc:
        return path, None, str(exc)


def module_name_from_lock_path(path: str) -> str:
    modules = re.findall(r"(?:^|/)node_modules/((?:@[^/]+/)?[^/]+)", path)
    return modules[-1] if modules else ""


def npm_parent_from_lock_path(path: str) -> str:
    modules = re.findall(r"(?:^|/)node_modules/((?:@[^/]+/)?[^/]+)", path)
    return modules[-2] if len(modules) > 1 else ""


def parse_package_json_direct_names(text: str) -> set[str]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return set()
    names: set[str] = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        names.update((data.get(section) or {}).keys())
    return names


def parse_npm_lock(text: str, path: str, direct_names: set[str]) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    data = json.loads(text)
    found: list[dict[str, Any]] = []

    def add(name: str, version: Any, lock_path: str, direct: bool, parent: str = "") -> None:
        if not name or not isinstance(version, str) or not version.strip():
            return
        if version.startswith(("workspace:", "file:", "git+", "http:" , "https:")):
            return
        found.append({
            "name": name,
            "version": version.strip(),
            "ecosystem": "npm",
            "file": lock_path,
            "direct": bool(direct),
            "parent": parent,
        })

    packages = data.get("packages")
    if isinstance(packages, dict):
        root_info = packages.get("") or {}
        lock_direct = set()
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            lock_direct.update((root_info.get(section) or {}).keys())
        if not direct_names:
            direct_names = lock_direct
        for package_path, package_info in packages.items():
            if not package_path or not isinstance(package_info, dict):
                continue
            name = package_info.get("name") or module_name_from_lock_path(package_path)
            if not name:
                continue
            module_count = len(re.findall(r"(?:^|/)node_modules/", package_path))
            is_direct = module_count == 1 and name in direct_names
            add(name, package_info.get("version"), path, is_direct, npm_parent_from_lock_path(package_path))
        return found, warnings

    def visit(items: Any, depth: int = 0, parent: str = "") -> None:
        if not isinstance(items, dict):
            return
        for name, item in items.items():
            if not isinstance(item, dict):
                continue
            direct = depth == 0 and (name in direct_names if direct_names else True)
            add(name, item.get("version"), path, direct, parent)
            visit(item.get("dependencies"), depth + 1, name)

    visit(data.get("dependencies"))
    if not found:
        warnings.append(f"{path}: no exact npm package versions were found in this lockfile")
    return found, warnings


REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]+\])?)\s*(===|==)\s*([^\s;,#]+)"
)


def parse_requirements(text: str, path: str) -> tuple[list[dict[str, Any]], list[str]]:
    found: list[dict[str, Any]] = []
    skipped = 0
    for original_line in text.splitlines():
        line = original_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            continue
        match = REQUIREMENT_RE.match(line)
        if not match:
            skipped += 1
            continue
        name = match.group(1).split("[", 1)[0]
        version = match.group(3).strip().strip("\"'")
        found.append({"name": name, "version": version, "ecosystem": "PyPI", "file": path, "direct": True, "parent": ""})
    warnings = []
    if skipped:
        warnings.append(
            f"{path}: {skipped} line(s) were not exact ==/=== pins and were skipped; "
            "use a lockfile for complete Python dependency coverage"
        )
    return found, warnings


PROPERTY_RE = re.compile(r"\$\{([^}]+)\}")


def parse_maven_pom(text: str, path: str) -> tuple[list[dict[str, Any]], list[str]]:
    root = SafeET.fromstring(text)
    properties: dict[str, str] = {}
    properties_element = next((child for child in list(root) if local_name(child.tag) == "properties"), None)
    if properties_element is not None:
        for child in list(properties_element):
            if child.text and child.text.strip():
                properties[local_name(child.tag)] = child.text.strip()

    project_version = child_text(root, "version")
    properties.setdefault("project.version", project_version)
    properties.setdefault("pom.version", project_version)

    def resolve(value: str) -> str:
        result = value.strip()
        for _ in range(8):
            new_value = PROPERTY_RE.sub(lambda match: properties.get(match.group(1), match.group(0)), result)
            if new_value == result:
                break
            result = new_value
        return result

    managed: dict[str, str] = {}
    for child in list(root):
        if local_name(child.tag) != "dependencyManagement":
            continue
        for block in list(child):
            if local_name(block.tag) != "dependencies":
                continue
            for dependency in list(block):
                if local_name(dependency.tag) != "dependency":
                    continue
                group = resolve(child_text(dependency, "groupId"))
                artifact = resolve(child_text(dependency, "artifactId"))
                version = resolve(child_text(dependency, "version"))
                if group and artifact and version and "${" not in version:
                    managed[f"{group}:{artifact}"] = version

    dependencies: list[dict[str, Any]] = []
    warnings: list[str] = []
    for child in list(root):
        if local_name(child.tag) != "dependencies":
            continue
        for dependency in list(child):
            if local_name(dependency.tag) != "dependency":
                continue
            group = resolve(child_text(dependency, "groupId"))
            artifact = resolve(child_text(dependency, "artifactId"))
            version = resolve(child_text(dependency, "version"))
            coordinate = f"{group}:{artifact}" if group and artifact else ""
            if coordinate and (not version or "${" in version):
                version = managed.get(coordinate, "")
            if not coordinate or not version or "${" in version:
                warnings.append(f"{path}: skipped a Maven dependency with a missing or unresolved version")
                continue
            dependencies.append({
                "name": coordinate,
                "version": version,
                "ecosystem": "Maven",
                "file": path,
                "direct": True,
                "parent": "",
            })
    return dependencies, warnings


def merge_dependencies(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        key = (item["ecosystem"], normalize_package_name(item["name"], item["ecosystem"]), item["version"])
        current = merged.get(key)
        if current is None:
            current = {**item, "files": [item["file"]]}
            merged[key] = current
        else:
            if item["file"] not in current["files"]:
                current["files"].append(item["file"])
            current["direct"] = current["direct"] or item["direct"]
            if not current.get("parent") and item.get("parent"):
                current["parent"] = item["parent"]
    result = list(merged.values())
    for item in result:
        item["files"].sort()
        item["file"] = item["files"][0]
    return sorted(result, key=lambda item: (item["ecosystem"], item["name"].lower(), item["version"]))


def parse_manifests(file_contents: dict[str, str], manifest_paths: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    all_dependencies: list[dict[str, Any]] = []
    warnings: list[str] = []
    package_jsons = {
        path: parse_package_json_direct_names(text)
        for path, text in file_contents.items()
        if path.rsplit("/", 1)[-1] == "package.json"
    }

    def direct_names_for_lock(lock_path: str) -> set[str]:
        directory = lock_path.rsplit("/", 1)[0] if "/" in lock_path else ""
        candidate = f"{directory}/package.json" if directory else "package.json"
        if candidate in package_jsons and package_jsons[candidate]:
            return package_jsons[candidate]
        return set()

    for path in manifest_paths:
        text = file_contents.get(path)
        if text is None:
            continue
        basename = path.rsplit("/", 1)[-1].lower()
        try:
            if basename in {"package-lock.json", "npm-shrinkwrap.json"}:
                dependencies, parse_warnings = parse_npm_lock(text, path, direct_names_for_lock(path))
            elif basename == "requirements.txt":
                dependencies, parse_warnings = parse_requirements(text, path)
            elif basename == "pom.xml":
                dependencies, parse_warnings = parse_maven_pom(text, path)
            else:
                continue
            all_dependencies.extend(dependencies)
            warnings.extend(parse_warnings)
        except Exception as exc:
            warnings.append(f"{path}: could not parse this manifest ({exc})")
    return merge_dependencies(all_dependencies), warnings


def scan_repository(repository_url: str, branch_override: str = "") -> dict[str, Any]:
    owner, repo, branch_in_url = parse_github_url(repository_url)
    owner_api, repo_api = quote(owner, safe=""), quote(repo, safe="")
    base_api = f"{GITHUB_API}/repos/{owner_api}/{repo_api}"
    repository_info = github_request_json(base_api)
    selected_branch = (branch_override or branch_in_url or repository_info.get("default_branch") or "main").strip()
    if not selected_branch:
        selected_branch = repository_info.get("default_branch") or "main"

    branch_info = github_request_json(f"{base_api}/branches/{quote(selected_branch, safe='')}")
    commit_sha = branch_info.get("commit", {}).get("sha")
    if not commit_sha:
        raise SupplyGuardError("GitHub did not return a commit for the selected branch.")

    tree = github_request_json(f"{base_api}/git/trees/{quote(commit_sha, safe='')}?recursive=1")
    all_paths = [
        item.get("path", "")
        for item in tree.get("tree", [])
        if item.get("type") == "blob" and item.get("path")
    ]
    manifest_names = {"package-lock.json", "npm-shrinkwrap.json", "requirements.txt", "pom.xml"}
    manifest_paths = sorted(path for path in all_paths if path.rsplit("/", 1)[-1].lower() in manifest_names)
    package_json_paths = sorted(path for path in all_paths if path.rsplit("/", 1)[-1].lower() == "package.json")
    requested_paths = sorted(set(manifest_paths + package_json_paths))
    warnings: list[str] = []
    if tree.get("truncated"):
        warnings.append("GitHub marked the repository file tree as truncated; some manifests may be missing.")
    if len(manifest_paths) > MAX_MANIFESTS:
        warnings.append(f"Only the first {MAX_MANIFESTS} dependency manifests were scanned.")
        manifest_paths = manifest_paths[:MAX_MANIFESTS]
        needed_dirs = {path.rsplit("/", 1)[0] if "/" in path else "" for path in manifest_paths}
        package_json_paths = [
            path for path in package_json_paths
            if (path.rsplit("/", 1)[0] if "/" in path else "") in needed_dirs
        ]
        requested_paths = sorted(set(manifest_paths + package_json_paths))

    tree_by_path = {item.get("path"): item for item in tree.get("tree", []) if item.get("type") == "blob"}
    file_contents: dict[str, str] = {}
    fetch_warnings: list[str] = []
    fetchable_paths: list[str] = []
    for path in requested_paths:
        size = tree_by_path.get(path, {}).get("size")
        if isinstance(size, int) and size > MAX_FILE_BYTES:
            fetch_warnings.append(f"{path}: skipped because it is larger than 1 MB")
        else:
            fetchable_paths.append(path)

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(fetch_raw_file, owner, repo, commit_sha, path): path
            for path in fetchable_paths
        }
        for future in as_completed(futures):
            path, content, error = future.result()
            if error:
                fetch_warnings.append(f"{path}: could not read file ({error})")
            elif content is not None:
                file_contents[path] = content
    warnings.extend(fetch_warnings)

    dependencies, parse_warnings = parse_manifests(file_contents, manifest_paths)
    warnings.extend(parse_warnings)
    full_name = repository_info.get("full_name", f"{owner}/{repo}")
    findings: list[dict[str, Any]] = []
    osv_status = "not_needed"
    if dependencies:
        osv_status = "complete"
        try:
            findings, osv_warnings = query_osv(dependencies, full_name)
            warnings.extend(osv_warnings)
        except SupplyGuardError as exc:
            osv_status = "failed"
            warnings.append(f"OSV lookup failed: {exc}")
    else:
        warnings.append("No exact dependency versions were parsed from the supported manifests.")

    repository = {
        "owner": owner,
        "name": repo,
        "full_name": full_name,
        "url": f"https://github.com/{owner}/{repo}",
        "branch": selected_branch,
        "commit": commit_sha,
    }
    return {
        "repository": repository,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "manifest_files": manifest_paths,
        "dependencies": dependencies,
        "findings": findings,
        "warnings": warnings,
        "osv_status": osv_status,
        "truncated_tree": bool(tree.get("truncated")),
        "repository_recommendations": build_repository_recommendations(all_paths, dependencies, warnings),
    }


def query_osv_batch(dependencies: list[dict[str, Any]]) -> list[list[str]]:
    all_ids: list[list[str]] = [[] for _ in dependencies]
    for start in range(0, len(dependencies), 100):
        chunk = dependencies[start:start + 100]
        queries = [
            {
                "package": {"name": dependency["name"], "ecosystem": dependency["ecosystem"]},
                "version": dependency["version"],
            }
            for dependency in chunk
        ]
        try:
            response = requests.post(
                OSV_API,
                json={"queries": queries},
                headers=JSON_HEADERS,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            body = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise SupplyGuardError(f"OSV batch query could not be completed: {exc}") from exc

        results = body.get("results", [])
        if len(results) != len(chunk):
            raise SupplyGuardError("OSV returned a different number of results than queried packages.")
        for offset, result in enumerate(results):
            ids = {vulnerability.get("id") for vulnerability in result.get("vulns", []) if vulnerability.get("id")}
            page_token = result.get("next_page_token")
            while page_token:
                query_with_token = dict(queries[offset])
                query_with_token["page_token"] = page_token
                try:
                    page_response = requests.post(
                        OSV_API,
                        json={"queries": [query_with_token]},
                        headers=JSON_HEADERS,
                        timeout=REQUEST_TIMEOUT,
                    )
                    page_response.raise_for_status()
                    page_body = page_response.json()
                except (requests.RequestException, ValueError) as exc:
                    raise SupplyGuardError(f"OSV advisory pagination failed: {exc}") from exc
                page_results = page_body.get("results", [])
                if not page_results:
                    break
                ids.update(
                    vulnerability.get("id")
                    for vulnerability in page_results[0].get("vulns", [])
                    if vulnerability.get("id")
                )
                page_token = page_results[0].get("next_page_token")
            all_ids[start + offset] = sorted(ids)
    return all_ids


def fetch_osv_record(vulnerability_id: str) -> dict[str, Any]:
    url = f"{OSV_VULN_API}/{quote(vulnerability_id, safe='')}"
    response = requests.get(url, headers=JSON_HEADERS, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    return response.json()


def cvss_severity(score: float) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW" if score > 0 else "UNRATED"


def severity_from_record(record: dict[str, Any]) -> str:
    database_specific = record.get("database_specific") or {}
    ecosystem_specific = record.get("ecosystem_specific") or {}
    for raw in (database_specific.get("severity"), ecosystem_specific.get("severity")):
        severity = normalize_finding_severity(raw)
        if severity != "UNRATED":
            return severity

    for score_record in record.get("severity", []) or []:
        raw_score = str(score_record.get("score", "")).strip()
        try:
            if re.fullmatch(r"\d+(?:\.\d+)?", raw_score):
                return cvss_severity(float(raw_score))
            upper = raw_score.upper()
            if upper.startswith("CVSS:4."):
                return normalize_finding_severity(CVSS4(raw_score).severities()[0])
            if upper.startswith("CVSS:3."):
                return normalize_finding_severity(CVSS3(raw_score).severities()[0])
            if upper.startswith("AV:"):
                return normalize_finding_severity(CVSS2(raw_score).severities()[0])
        except Exception:
            continue
    return "UNRATED"


def version_compare(left: str, right: str) -> int:
    try:
        left_version, right_version = Version(left.lstrip("vV")), Version(right.lstrip("vV"))
        return (left_version > right_version) - (left_version < right_version)
    except InvalidVersion:
        def fallback_key(value: str) -> tuple[tuple[int, Any], ...]:
            parts = re.findall(r"\d+|[A-Za-z]+", value)
            return tuple((0, int(part)) if part.isdigit() else (1, part.lower()) for part in parts)
        left_key, right_key = fallback_key(left), fallback_key(right)
        return (left_key > right_key) - (left_key < right_key)


def version_is_in_osv_range(version: str, events: list[dict[str, str]]) -> bool | None:
    active = False
    saw_introduced = False
    for event in events:
        if "introduced" in event:
            saw_introduced = True
            bound = str(event["introduced"])
            if bound == "0":
                active = True
            else:
                active = version_compare(version, bound) >= 0
        elif "fixed" in event:
            bound = str(event["fixed"])
            if version_compare(version, bound) >= 0:
                active = False
        elif "last_affected" in event:
            bound = str(event["last_affected"])
            active = version_compare(version, bound) <= 0
        elif "limit" in event:
            bound = str(event["limit"])
            if version_compare(version, bound) >= 0:
                active = False
    return active if saw_introduced else None


def fixed_version_for(record: dict[str, Any], dependency: dict[str, Any]) -> str:
    matching_affected = []
    for affected in record.get("affected", []) or []:
        package = affected.get("package") or {}
        if package.get("ecosystem") != dependency["ecosystem"]:
            continue
        if normalize_package_name(package.get("name", ""), dependency["ecosystem"]) != normalize_package_name(
            dependency["name"], dependency["ecosystem"]
        ):
            continue
        matching_affected.append(affected)

    safe_candidates: set[str] = set()
    fallback_candidates: set[str] = set()
    for affected in matching_affected:
        explicit_versions = {str(value) for value in affected.get("versions", []) or []}
        explicit_match = dependency["version"] in explicit_versions
        for version_range in affected.get("ranges", []) or []:
            events = version_range.get("events", []) or []
            fixes = {str(event["fixed"]) for event in events if event.get("fixed")}
            fallback_candidates.update(fixes)
            affected_match = version_is_in_osv_range(dependency["version"], events)
            if affected_match is True or explicit_match:
                safe_candidates.update(fixes)

    candidates = safe_candidates or (fallback_candidates if len(fallback_candidates) == 1 else set())
    if not candidates:
        return ""
    return sorted(candidates, key=cmp_to_key(version_compare))[0]


def safe_reference_url(url: Any) -> str:
    if not isinstance(url, str):
        return ""
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return url.strip()


def advisory_url_for(record: dict[str, Any]) -> str:
    references = record.get("references", []) or []
    priority = {"ADVISORY": 0, "PACKAGE": 1, "WEB": 2, "ARTICLE": 3, "REPORT": 4, "FIX": 5}
    for reference in sorted(references, key=lambda item: priority.get(str(item.get("type", "")).upper(), 9)):
        url = safe_reference_url(reference.get("url"))
        if url:
            return url
    identifier = record.get("id", "")
    return f"https://osv.dev/vulnerability/{quote(identifier, safe='')}" if identifier else "https://osv.dev/"


def cve_link_for(aliases: list[str]) -> tuple[str, str]:
    cve_id = next((alias for alias in aliases if re.fullmatch(r"CVE-\d{4}-\d+", alias, re.IGNORECASE)), "")
    if not cve_id:
        return "", ""
    return cve_id.upper(), f"https://nvd.nist.gov/vuln/detail/{quote(cve_id.upper(), safe='')}"


def major_upgrade(current: str, fixed: str) -> bool:
    try:
        current_release = Version(current.lstrip("vV")).release
        fixed_release = Version(fixed.lstrip("vV")).release
        return bool(current_release and fixed_release and current_release[0] != fixed_release[0])
    except InvalidVersion:
        current_major = re.match(r"\D*(\d+)", current)
        fixed_major = re.match(r"\D*(\d+)", fixed)
        return bool(current_major and fixed_major and current_major.group(1) != fixed_major.group(1))


def make_recommendation(dependency: dict[str, Any], advisory: dict[str, Any]) -> dict[str, str]:
    fixed = advisory.get("fixed_version", "")
    ecosystem = dependency["ecosystem"]
    name = dependency["name"]
    if fixed:
        breaking = major_upgrade(dependency["version"], fixed)
        if dependency.get("direct"):
            action = f"Update {name} to {fixed} in the direct dependency manifest, then regenerate the lockfile."
        elif dependency.get("parent"):
            action = (
                f"Update the parent dependency {dependency['parent']} first. It brings in vulnerable "
                f"{name}; verify the new lockfile resolves {name} to {fixed} or later."
            )
        else:
            action = (
                f"Update the direct parent that brings in {name}, then regenerate the lockfile and "
                f"confirm the resolved {name} version is {fixed} or later."
            )
        if breaking:
            rationale = "The candidate fix changes the first version component; treat it as a potentially breaking upgrade."
        else:
            rationale = "OSV lists this fixed version for the matching package and affected version range."
        if ecosystem == "npm":
            validation = "Review package.json and package-lock.json together, then run npm test (and the project build)."
        elif ecosystem == "PyPI":
            validation = "Update the pinned requirement, install from the project's lock process, then run its test suite."
        else:
            validation = "Update the Maven coordinate in pom.xml or dependency management, then run mvn test."
        return {
            "action": action,
            "target": fixed,
            "rationale": rationale,
            "validation": validation,
            "risk": "Potentially breaking" if breaking else "Review lockfile diff",
        }

    if dependency.get("direct"):
        action = (
            f"No fixed release is listed for {name}. Review the upstream advisory, assess whether the "
            "feature is used, and consider a maintained replacement or temporary mitigation."
        )
    else:
        action = (
            f"No fixed release is listed for transitive dependency {name}. Contact or update its parent, "
            "review a compatible override only if the ecosystem supports it, and consider a replacement."
        )
    return {
        "action": action,
        "target": "No fixed version published by OSV",
        "rationale": "A safe target version could not be derived from the matching OSV affected ranges.",
        "validation": "After any mitigation or replacement, rescan the same commit and run the repository's test suite.",
        "risk": "No known fix",
    }


def build_finding_key(repository: dict[str, str], dependency: dict[str, Any], advisory_id: str) -> str:
    raw = "|".join([
        repository["full_name"].lower(),
        dependency["ecosystem"],
        normalize_package_name(dependency["name"], dependency["ecosystem"]),
        advisory_id,
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def query_osv(
    dependencies: list[dict[str, Any]], repository_full_name: str
) -> tuple[list[dict[str, Any]], list[str]]:
    ids_by_dependency = query_osv_batch(dependencies)
    all_ids = sorted({identifier for identifiers in ids_by_dependency for identifier in identifiers})
    records: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []

    def load_record(identifier: str) -> tuple[str, dict[str, Any] | None, str | None]:
        try:
            return identifier, fetch_osv_record(identifier), None
        except (requests.RequestException, ValueError) as exc:
            return identifier, None, str(exc)

    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = [executor.submit(load_record, identifier) for identifier in all_ids]
        for future in as_completed(futures):
            identifier, record, error = future.result()
            if record is not None:
                records[identifier] = record
            else:
                warnings.append(f"Could not load full OSV advisory {identifier}: {error}")

    findings: list[dict[str, Any]] = []
    for dependency, identifiers in zip(dependencies, ids_by_dependency):
        for identifier in identifiers:
            record = records.get(identifier) or {"id": identifier, "aliases": [], "references": []}
            aliases = [str(alias) for alias in record.get("aliases", []) or []]
            cve_id, cve_url = cve_link_for(aliases)
            details = str(record.get("details", "") or "")
            advisory = {
                "id": identifier,
                "aliases": aliases,
                "summary": record.get("summary") or (details.splitlines()[0] if details else "Security advisory"),
                "details": details[:4000],
                "severity": severity_from_record(record),
                "url": advisory_url_for(record),
                "cve_id": cve_id,
                "cve_url": cve_url,
                "published": record.get("published", ""),
                "modified": record.get("modified", ""),
            }
            advisory["fixed_version"] = fixed_version_for(record, dependency)
            finding = {
                "key": build_finding_key(
                    {"full_name": repository_full_name},
                    dependency,
                    identifier,
                ),
                "package": {**dependency, "files": list(dependency.get("files", [dependency.get("file", "")]))},
                "advisory": advisory,
            }
            findings.append(finding)
    findings.sort(key=lambda finding: (
        SEVERITY_ORDER.get(finding["advisory"]["severity"], 9),
        finding["package"]["name"].lower(),
        finding["advisory"]["id"],
    ))
    return findings, warnings


def build_repository_recommendations(
    paths: list[str], dependencies: list[dict[str, Any]], warnings: list[str]
) -> list[str]:
    lowered = {path.lower() for path in paths}
    recommendations: list[str] = []
    if any(dep["ecosystem"] == "npm" for dep in dependencies) and not any(
        path.rsplit("/", 1)[-1] in {"package-lock.json", "npm-shrinkwrap.json"} for path in lowered
    ):
        recommendations.append("Commit an npm lockfile so exact transitive versions can be scanned and reproduced.")
    if any(dep["ecosystem"] == "PyPI" for dep in dependencies):
        recommendations.append("Use a generated Python lockfile in CI; requirements.txt pins alone may omit transitive dependencies.")
    if any(dep["ecosystem"] == "Maven" for dep in dependencies):
        recommendations.append("Resolve the Maven dependency tree in CI to include transitive packages not declared in pom.xml.")
    if not any(path.endswith(".github/dependabot.yml") or path.endswith(".github/dependabot.yaml") for path in lowered):
        recommendations.append("Add .github/dependabot.yml to propose reviewed dependency updates on a schedule.")
    if not any(path.startswith(".github/workflows/") for path in lowered):
        recommendations.append("Add a GitHub Actions workflow to rescan pull requests and run the project's tests.")
    if warnings:
        recommendations.append("Review scan warnings in the exported JSON report before treating this scan as complete.")
    if not recommendations:
        recommendations.append("Keep dependency lockfiles committed and rescan after each dependency change.")
    return recommendations[:6]


def finding_status(finding: dict[str, Any]) -> str:
    return st.session_state.get("finding_statuses", {}).get(finding["key"], "open")


def findings_with_status(scan: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    statuses = st.session_state.get("finding_statuses", {})
    for finding in scan.get("findings", []):
        result.append({**finding, "status": statuses.get(finding["key"], "open")})
    return result


def filter_findings_for_display(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    severity_filter = normalize_severity_filter(st.session_state.get("severity_filter", "all"))
    status_filter = normalize_status_filter(st.session_state.get("status_filter", "all"))
    query = str(st.session_state.get("finding_search", "") or "").strip().lower()
    visible = []
    for finding in findings:
        severity = normalize_finding_severity(finding.get("advisory", {}).get("severity"))
        status = str(finding.get("status", "open")).lower()
        if severity_filter != "all" and severity != severity_filter:
            continue
        if status_filter != "all" and status != status_filter:
            continue
        package = finding.get("package", {})
        advisory = finding.get("advisory", {})
        search_blob = " ".join([
            str(package.get("name", "")),
            str(package.get("version", "")),
            str(advisory.get("id", "")),
            str(advisory.get("cve_id", "")),
            str(advisory.get("summary", "")),
            " ".join(package.get("files", []) or []),
        ]).lower()
        if query and query not in search_blob:
            continue
        visible.append(finding)
    return visible


def make_table_rows(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for finding in findings:
        package, advisory = finding["package"], finding["advisory"]
        rows.append({
            "Severity": advisory.get("severity", "UNRATED"),
            "Package": package.get("name", ""),
            "Version": package.get("version", ""),
            "Advisory ID": advisory.get("id", ""),
            "CVE": advisory.get("cve_url", ""),
            "Relationship": "Direct" if package.get("direct") else "Transitive",
            "Affected file": ", ".join(package.get("files", [])),
            "Fixed in": advisory.get("fixed_version") or "—",
            "Status": finding.get("status", "open").title(),
        })
    return rows


def render_findings_table(findings: list[dict[str, Any]]) -> None:
    rows = make_table_rows(findings)
    st.dataframe(
        rows,
        hide_index=True,
        width="stretch",
        column_config={
            "Severity": st.column_config.TextColumn("Severity", width="small"),
            "Package": st.column_config.TextColumn("Package", width="medium"),
            "CVE": st.column_config.LinkColumn(
                "CVE",
                display_text=r"https://nvd\.nist\.gov/vuln/detail/(CVE-\d{4}-\d+)",
                width="medium",
            ),
        },
    )


def status_selector(finding: dict[str, Any], key_prefix: str = "finding-status") -> None:
    key = f"{key_prefix}-{finding['key']}"
    statuses = st.session_state.setdefault("finding_statuses", {})
    if key not in st.session_state:
        st.session_state[key] = statuses.get(finding["key"], "open")
    status = st.selectbox(
        "Finding status",
        options=("open", "fixed", "dismissed"),
        format_func=str.title,
        key=key,
    )
    statuses[finding["key"]] = status


def recommendation_for_finding(finding: dict[str, Any]) -> dict[str, str]:
    return make_recommendation(finding["package"], finding["advisory"])


def render_recommendation(finding: dict[str, Any]) -> None:
    package, advisory = finding["package"], finding["advisory"]
    recommendation = recommendation_for_finding(finding)
    cve_id = advisory.get("cve_id")
    st.markdown(
        f"**{advisory.get('severity', 'UNRATED')}** · `{package['name']}@{package['version']}` "
        f"· {advisory.get('id', 'Advisory')}"
    )
    st.write(recommendation["action"])
    st.caption(f"Recommended target: {recommendation['target']} · {recommendation['risk']}")
    st.caption(f"Why: {recommendation['rationale']}")
    st.caption(f"Affected file(s): {', '.join(package.get('files', [])) or 'unknown'}")
    if not package.get("direct") and package.get("parent"):
        st.caption(f"Detected parent path: {package['parent']} → {package['name']}")
    st.write(f"**Validate:** {recommendation['validation']}")
    if cve_id and advisory.get("cve_url"):
        st.markdown(f"[Open {cve_id}]({advisory['cve_url']})")
    status_selector(finding)


def apply_scan_statuses(new_scan: dict[str, Any], old_scan: dict[str, Any] | None) -> None:
    statuses = st.session_state.setdefault("finding_statuses", {})
    new_keys = {finding["key"] for finding in new_scan.get("findings", [])}
    if old_scan:
        for old_finding in old_scan.get("findings", []):
            if old_finding["key"] not in new_keys and statuses.get(old_finding["key"], "open") == "open":
                statuses[old_finding["key"]] = "fixed"
    for finding in new_scan.get("findings", []):
        if statuses.get(finding["key"]) == "fixed":
            statuses[finding["key"]] = "open"


def create_export(scan: dict[str, Any], findings: list[dict[str, Any]]) -> tuple[str, str]:
    report = {
        "product": APP_TITLE,
        "repository": scan["repository"],
        "scanned_at": scan["scanned_at"],
        "osv_status": scan["osv_status"],
        "summary": {
            "dependencies": len(scan.get("dependencies", [])),
            "findings": len(scan.get("findings", [])),
            "open": sum(item.get("status") == "open" for item in findings),
            "fixed": sum(item.get("status") == "fixed" for item in findings),
            "dismissed": sum(item.get("status") == "dismissed" for item in findings),
        },
        "manifest_files": scan.get("manifest_files", []),
        "warnings": scan.get("warnings", []),
        "findings": [
            {
                **finding,
                "recommendation": recommendation_for_finding(finding),
            }
            for finding in findings
        ],
    }
    json_text = json.dumps(report, indent=2, ensure_ascii=False)
    csv_buffer = io.StringIO()
    columns = [
        "severity", "package", "version", "ecosystem", "advisory_id", "cve_id", "advisory_url",
        "fixed_version", "status", "relationship", "affected_files", "recommendation",
    ]
    writer = csv.DictWriter(csv_buffer, fieldnames=columns)
    writer.writeheader()
    for finding in findings:
        package, advisory = finding["package"], finding["advisory"]
        writer.writerow({
            "severity": advisory.get("severity", "UNRATED"),
            "package": package.get("name", ""),
            "version": package.get("version", ""),
            "ecosystem": package.get("ecosystem", ""),
            "advisory_id": advisory.get("id", ""),
            "cve_id": advisory.get("cve_id", ""),
            "advisory_url": advisory.get("url", ""),
            "fixed_version": advisory.get("fixed_version", ""),
            "status": finding.get("status", "open"),
            "relationship": "direct" if package.get("direct") else "transitive",
            "affected_files": "; ".join(package.get("files", [])),
            "recommendation": recommendation_for_finding(finding)["action"],
        })
    return json_text, csv_buffer.getvalue()


def render_sidebar() -> tuple[str, bool, str, str]:
    with st.sidebar:
        st.markdown("# 🛡️ SupplyGuard")
        st.caption("Open source dependency security")
        page = st.radio("Workspace", ["Overview", "Findings", "Recommendations", "Scan history", "Reports"], key="active_page")
        st.divider()
        st.markdown("### Scan a public repository")
        with st.form("repository-scan-form"):
            repo_url = st.text_input("GitHub URL", placeholder="https://github.com/owner/repository")
            branch = st.text_input("Branch (optional)", placeholder="Uses the default branch")
            submitted = st.form_submit_button("Scan repository", type="primary", width="stretch")
        st.caption("Supported manifests: npm lockfiles, pinned requirements.txt, Maven pom.xml")
        st.divider()
        st.markdown("### Finding filters")

        # Normalize widget state before the keyed widgets are instantiated.
        st.session_state["severity_filter"] = normalize_severity_filter(
            st.session_state.get("severity_filter", "all")
        )
        st.session_state["status_filter"] = normalize_status_filter(
            st.session_state.get("status_filter", "all")
        )
        if not isinstance(st.session_state.get("finding_search"), str):
            st.session_state["finding_search"] = ""

        st.selectbox(
            "Severity",
            options=SEVERITY_FILTERS,
            format_func=lambda value: "All severities" if value == "all" else value.title(),
            key="severity_filter",
        )
        st.selectbox(
            "Status",
            options=STATUS_FILTERS,
            format_func=lambda value: "All statuses" if value == "all" else value.title(),
            key="status_filter",
        )
        st.text_input("Search findings", key="finding_search", placeholder="Package, CVE, advisory, file…")
        st.button("Clear filters", key="clear-finding-filters", on_click=clear_finding_filters, width="stretch")
        st.caption("Filters affect displayed rows only. They do not change scans or OSV lookups.")
    return page, submitted, repo_url, branch


def render_overview(scan: dict[str, Any], all_findings: list[dict[str, Any]], visible_findings: list[dict[str, Any]]) -> None:
    repository = scan["repository"]
    open_count = sum(item["status"] == "open" for item in all_findings)
    high_count = sum(item["advisory"].get("severity") in {"CRITICAL", "HIGH"} for item in all_findings)
    st.markdown(
        f"**{len(scan.get('dependencies', []))} dependencies checked**  ·  "
        f"**{len(all_findings)} total findings**  ·  "
        f"**{open_count} open**  ·  **{high_count} critical / high**"
    )
    st.markdown(
        f"**Repository:** [{repository['full_name']}]({repository['url']})  "
        f"· **Branch:** `{repository['branch']}`  · **Commit:** `{repository['commit'][:12]}`"
    )
    st.caption(f"Scanned {scan['scanned_at']} · OSV lookup: {scan['osv_status']}")
    render_detected_stack(scan)

    st.subheader("Highest-priority findings")
    st.caption(f"Showing {len(visible_findings)} of {len(all_findings)} findings with the current filters.")
    if visible_findings:
        render_findings_table(visible_findings[:10])
    elif all_findings:
        st.info("No findings match these filters. Clear the filters to show all findings.")
    elif scan.get("osv_status") == "complete":
        st.success("No vulnerabilities were returned for the exact package versions in this scan.")
    elif scan.get("osv_status") == "failed":
        st.error("The dependency files were scanned, but the OSV lookup failed. This is not a clean scan.")
    else:
        st.info("No supported exact dependency versions were found in the scanned manifests.")

    st.subheader("Repository recommendations")
    for recommendation in scan.get("repository_recommendations", []):
        st.markdown(f"- {recommendation}")


def render_detected_stack(scan: dict[str, Any]) -> None:
    stack_specs = [
        {
            "ecosystem": "npm",
            "label": "JavaScript / Node.js",
            "manifests": {"package-lock.json", "npm-shrinkwrap.json"},
            "recognizable": {
                "Angular": {"@angular/core"},
                "Express": {"express"},
                "NestJS": {"@nestjs/core"},
                "Next.js": {"next"},
                "React": {"react"},
                "Svelte": {"svelte"},
                "Vue": {"vue"},
            },
        },
        {
            "ecosystem": "PyPI",
            "label": "Python",
            "manifests": {"requirements.txt"},
            "recognizable": {
                "Django": {"django"},
                "FastAPI": {"fastapi"},
                "Flask": {"flask"},
                "Streamlit": {"streamlit"},
            },
        },
        {
            "ecosystem": "Maven",
            "label": "Java / Maven",
            "manifests": {"pom.xml"},
            "recognizable": {},
        },
    ]
    manifest_files = scan.get("manifest_files", [])
    dependencies = scan.get("dependencies", [])

    st.subheader("Detected technology stack")
    st.caption("Detected from the supported dependency manifests and package names in this repository.")
    found_stack = False
    for spec in stack_specs:
        files = [
            path for path in manifest_files
            if path.rsplit("/", 1)[-1].lower() in spec["manifests"]
        ]
        if not files:
            continue
        found_stack = True
        stack_dependencies = [item for item in dependencies if item.get("ecosystem") == spec["ecosystem"]]
        package_names = {str(item.get("name", "")).lower() for item in stack_dependencies}
        frameworks = [
            name for name, recognized_names in spec["recognizable"].items()
            if package_names.intersection(recognized_names)
        ]
        if spec["ecosystem"] == "Maven":
            if any(name.startswith("org.springframework.") or "spring-boot-starter" in name for name in package_names):
                frameworks.append("Spring")
            if any(name.startswith("io.quarkus:") for name in package_names):
                frameworks.append("Quarkus")
            if any(name.startswith("org.hibernate:") for name in package_names):
                frameworks.append("Hibernate")

        dependency_count = len(stack_dependencies)
        dependency_label = "dependency version" if dependency_count == 1 else "dependency versions"
        detail = f"{dependency_count} parsed {dependency_label}"
        if frameworks:
            detail += f" · Recognized: {', '.join(sorted(frameworks))}"
        shown_files = ", ".join(f"`{path}`" for path in files[:4])
        if len(files) > 4:
            shown_files += f", and {len(files) - 4} more"
        st.markdown(f"- **{spec['label']}** — {detail} · Manifests: {shown_files}")

    if not found_stack:
        st.info("No supported stack manifests were found. Detection currently covers npm lockfiles, requirements.txt, and Maven pom.xml.")


def render_findings(all_findings: list[dict[str, Any]], visible_findings: list[dict[str, Any]]) -> None:
    st.subheader("Vulnerability findings")
    st.caption(f"Showing {len(visible_findings)} of {len(all_findings)} total findings. Scan totals never use the filtered count.")
    if visible_findings:
        render_findings_table(visible_findings)
        st.markdown("### Finding details and recommendations")
        for finding in visible_findings:
            package = finding["package"]
            advisory = finding["advisory"]
            heading = f"{advisory.get('severity', 'UNRATED')} · {package['name']}@{package['version']} · {advisory['id']}"
            with st.expander(heading):
                render_recommendation(finding)
    elif all_findings:
        st.info("No findings match these filters. Use Clear filters in the sidebar to show all findings.")
    else:
        st.info("No findings are available for the current scan.")


def render_recommendations(scan: dict[str, Any], visible_findings: list[dict[str, Any]]) -> None:
    st.subheader("Recommended next steps")
    st.caption("These are reviewable suggestions. SupplyGuard does not edit your repository or open a pull request.")
    for recommendation in scan.get("repository_recommendations", []):
        st.markdown(f"- {recommendation}")
    st.divider()
    if not visible_findings:
        if scan.get("findings"):
            st.info("No finding recommendations match the current filters. Clear filters to see every recommendation.")
        else:
            st.success("No advisory-specific fixes are needed for the findings returned by this scan.")
        return
    for finding in visible_findings:
        advisory, package = finding["advisory"], finding["package"]
        title = f"{advisory.get('severity', 'UNRATED')} · {package['name']}@{package['version']}"
        with st.expander(title):
            render_recommendation(finding)


def render_history(history: list[dict[str, Any]]) -> None:
    st.subheader("Scan history")
    if not history:
        st.info("Completed scans in this browser session will appear here.")
        return
    st.dataframe(history, hide_index=True, width="stretch")
    st.caption("This prototype keeps history in the active Streamlit session. A shared team history needs a backend database.")


def render_reports(scan: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    st.subheader("Export this scan")
    st.write("The report includes the repository commit, dependency versions, advisory and CVE links, status, and remediation suggestion.")
    json_text, csv_text = create_export(scan, findings)
    repository_slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", scan["repository"]["full_name"]).strip("-").lower()
    col_json, col_csv = st.columns(2)
    with col_json:
        st.download_button(
            "Download JSON",
            data=json_text,
            file_name=f"{repository_slug}-supplyguard-report.json",
            mime="application/json",
            width="stretch",
        )
    with col_csv:
        st.download_button(
            "Download CSV",
            data=csv_text,
            file_name=f"{repository_slug}-supplyguard-report.csv",
            mime="text/csv",
            width="stretch",
        )
    st.caption("Exports contain all findings, including findings hidden by the current display filters.")


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon="🛡️", layout="wide")
    st.markdown(
        """
        <style>
        .block-container {max-width: 1420px; padding-top: 2rem;}
        [data-testid="stSidebar"] {border-right: 1px solid #e8edf2;}
        [data-testid="stAppDeployButton"], [data-testid="stDeployButton"], .stAppDeployButton {display: none !important;}
        h1, h2, h3 {letter-spacing: -0.025em;}
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.session_state.setdefault("latest_scan", None)
    st.session_state.setdefault("scan_history", [])
    st.session_state.setdefault("finding_statuses", {})
    page, submitted, repository_url, branch = render_sidebar()

    st.title("SupplyGuard")
    st.caption("Find vulnerable open-source dependencies and get a clear, reviewable next step.")
    if submitted:
        try:
            with st.spinner("Reading repository manifests and checking OSV advisories…"):
                scan = scan_repository(repository_url, branch)
            old_scan = st.session_state.get("latest_scan")
            apply_scan_statuses(scan, old_scan)
            st.session_state["latest_scan"] = scan
            history_item = {
                "Scanned at": scan["scanned_at"],
                "Repository": scan["repository"]["full_name"],
                "Branch": scan["repository"]["branch"],
                "Commit": scan["repository"]["commit"][:12],
                "Dependencies": len(scan["dependencies"]),
                "Findings": len(scan["findings"]),
                "OSV lookup": scan["osv_status"],
            }
            st.session_state["scan_history"] = [
                history_item,
                *[
                    item for item in st.session_state["scan_history"]
                    if not (item.get("Repository") == history_item["Repository"] and item.get("Commit") == history_item["Commit"])
                ],
            ][:25]
            st.success(
                f"Scan finished for {scan['repository']['full_name']} at {scan['repository']['commit'][:12]}: "
                f"{len(scan['dependencies'])} package versions checked, {len(scan['findings'])} advisory matches."
            )
        except SupplyGuardError as exc:
            st.error(str(exc))
        except Exception as exc:  # Keep unexpected scan failures visible instead of looking like a clean scan.
            st.error(f"The scan could not be completed: {exc}")

    scan = st.session_state.get("latest_scan")
    if scan is None:
        st.info("Paste a public GitHub repository URL in the sidebar and select **Scan repository** to begin.")
        st.markdown("#### What this prototype scans")
        st.write("npm package-lock.json / npm-shrinkwrap.json, exact-pinned Python requirements.txt, and direct Maven pom.xml dependencies.")
        st.warning("Only public repositories are supported. Python and Maven transitive dependencies require generated lockfiles or a resolved dependency tree for complete coverage.")
        return

    all_findings = findings_with_status(scan)
    visible_findings = filter_findings_for_display(all_findings)

    if page == "Overview":
        render_overview(scan, all_findings, visible_findings)
    elif page == "Findings":
        render_findings(all_findings, visible_findings)
    elif page == "Recommendations":
        render_recommendations(scan, visible_findings)
    elif page == "Scan history":
        render_history(st.session_state.get("scan_history", []))
    elif page == "Reports":
        render_reports(scan, all_findings)


if __name__ == "__main__":
    main()

