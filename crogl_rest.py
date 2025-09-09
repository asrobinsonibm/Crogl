#!/usr/bin/env python3
"""
Fetch all GitHub Global Security Advisories via REST, save JSONs grouped by severity,
zip them (low/moderate/high/critical), and produce a CSV with one row per vulnerability.

Usage (GitHub.com):
  export GITHUB_TOKEN=ghp_yourCLASSICtoken
  python3 fetch_ghsas_rest.py --out ./ghsa_rest_export

Usage (GHES):
  python3 fetch_ghsas_rest.py --out ./ghsa_rest_export \
    --api-base https://<your-ghes-host>/api/v3 --token ghp_yourCLASSICtoken
"""

import os
import sys
import csv
import json
import time
import argparse
import zipfile
import datetime as _dt
from pathlib import Path
from typing import Dict, Any, List, Optional

import requests

API_BASE_DEFAULT = "https://api.github.com"  # REST base for GitHub.com

# REST returns severities: unknown|low|medium|high|critical
# buckets; 
SEV_MAP = {
    "unknown": "low",
    "low": "low",
    "medium": "moderate",
    "high": "high",
    "critical": "critical",
}
SEVERITY_ORDER = ["low", "moderate", "high", "critical"]

# Optional global throttle (seconds) between REST requests
MIN_INTERVAL = float(os.getenv("GHSARL_MIN_INTERVAL", "0"))

# -------------------------  auth -------------------------

def gh_headers(token: str) -> Dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "ghsa-rest-exporter/1.1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h

def verify_token_rest(api_base: str, token: str):
    """Fail fast with a clear message if token is bad; print login on success."""
    url = f"{api_base.rstrip('/')}/user"
    try:
        r = requests.get(url, headers=gh_headers(token), timeout=30)
    except requests.RequestException as e:
        raise SystemExit(f"Failed to reach {url}: {e}")
    if r.status_code == 401:
        raise SystemExit(
            "GitHub token was rejected (401 Unauthorized).\n"
            "Fixes:\n"
            " - Use a Personal Access Token (classic) (ghp_...).\n"
            " - If your org uses SAML SSO, Authorize the token for that org.\n"
            " - Ensure no quotes/newlines in the value.\n"
        )
    try:
        r.raise_for_status()
    except requests.HTTPError as e:
        raise SystemExit(f"GitHub returned {r.status_code}: {e}\nBody: {r.text[:500]}")
    data = r.json()
    login = data.get("login", "<unknown>")
    print(f"[*] Token OK. Authenticated as: {login} @ {api_base}", file=sys.stderr)

def _sleep_until_reset(resp: requests.Response):
    """Wait until REST rate-limit reset if headers are present; else a safe default."""
    now = int(time.time())
    reset_hdr = resp.headers.get("X-RateLimit-Reset") or resp.headers.get("x-ratelimit-reset")
    if reset_hdr and str(reset_hdr).isdigit():
        wait = max(1, int(reset_hdr) - now)
        print(f"[rate-limit] waiting {wait}s until header reset…", file=sys.stderr)
        time.sleep(wait)
        return
    # Fallback if headers missing: wait 60s
    print("[rate-limit] no reset header; sleeping 60s…", file=sys.stderr)
    time.sleep(60)

def rest_get(url: str, token: str, params: Optional[dict] = None, max_retries: int = 5) -> requests.Response:
    """GET with retry, global pacing, and rate-limit handling."""
    for attempt in range(1, max_retries + 1):
        if MIN_INTERVAL > 0:
            time.sleep(MIN_INTERVAL)
        try:
            r = requests.get(url, headers=gh_headers(token), params=params, timeout=60)
        except requests.RequestException as e:
            if attempt == max_retries:
                raise
            sleep_s = min(60, 2 ** attempt)
            print(f"[network] {e} — retry {attempt}/{max_retries} after {sleep_s}s", file=sys.stderr)
            time.sleep(sleep_s)
            continue

        if r.status_code in (403, 429):  # primary or secondary rate limit
            ra = r.headers.get("Retry-After")
            if ra and str(ra).isdigit():
                wait = max(1, int(ra))
                print(f"[rate-limit] Retry-After={wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            _sleep_until_reset(r)
            continue

        if r.status_code >= 500:
            if attempt == max_retries:
                r.raise_for_status()
            sleep_s = min(60, 2 ** attempt)
            print(f"[{r.status_code}] retry {attempt}/{max_retries} after {sleep_s}s", file=sys.stderr)
            time.sleep(sleep_s)
            continue

        r.raise_for_status()
        return r

    raise RuntimeError("Exceeded maximum retries for REST GET")

# ------------------------- FS -------------------------

def ensure_dirs(base_out: Path) -> Dict[str, Path]:
    adv_base = base_out / "advisories"
    zips_base = base_out / "zips"
    adv_base.mkdir(parents=True, exist_ok=True)
    zips_base.mkdir(parents=True, exist_ok=True)
    sev_paths = {}
    for sev in SEVERITY_ORDER:
        p = adv_base / sev
        p.mkdir(parents=True, exist_ok=True)
        sev_paths[sev] = p
    return {"advisories_base": adv_base, "zips_base": zips_base, **sev_paths}

def write_advisory_json(advisory: Dict[str, Any], out_dir: Path):
    ghsa = (advisory.get("ghsa_id") or advisory.get("id") or "UNKNOWN").replace("/", "_")
    path = out_dir / f"{ghsa}.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(advisory, f, ensure_ascii=False, indent=2)

def zip_by_severity(sev_dir_map: Dict[str, Path], zips_base: Path):
    zips_base.mkdir(parents=True, exist_ok=True)
    for sev in SEVERITY_ORDER:
        folder = sev_dir_map[sev]
        zip_path = zips_base / f"advisories_{sev}.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for json_file in folder.glob("*.json"):
                zf.write(json_file, arcname=json_file.name)
        print(f"[zip] {zip_path} -> {sum(1 for _ in folder.glob('*.json'))} files", file=sys.stderr)

# ------------------------- CSV -------------------------

def build_csv_rows_from_advisory(a: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return CSV rows for a single advisory. Tolerates shape differences."""
    rows: List[Dict[str, Any]] = []

    ghsa_id = a.get("ghsa_id")
    severity_raw = (a.get("severity") or "low").lower()
    severity = SEV_MAP.get(severity_raw, "low")
    summary = (a.get("summary") or "").replace("\n", " ").strip()
    html_url = a.get("html_url") or a.get("url") or a.get("permalink")
    published_at = a.get("published_at")
    updated_at = a.get("updated_at")
    withdrawn_at = a.get("withdrawn_at")
    github_reviewed_at = a.get("github_reviewed_at")
    nvd_published_at = a.get("nvd_published_at")

    # CVSS: prefer v4/v3 from cvss_severities; fall back to cvss
    cvss = a.get("cvss") or {}
    cvss_score = cvss.get("score")
    cvss_vector = cvss.get("vector_string")
    if cvss_score is None or cvss_vector is None:
        cs = a.get("cvss_severities") or {}
        v4 = cs.get("cvss_v4") or {}
        v3 = cs.get("cvss_v3") or {}
        if v4.get("score") is not None:
            cvss_score = v4.get("score")
            cvss_vector = v4.get("vector_string")
        elif v3.get("score") is not None:
            cvss_score = v3.get("score")
            cvss_vector = v3.get("vector_string")

    # lists of objects
    def _norm_ids(ids, kind): return [i.get("value") for i in (ids or []) if i.get("type") == kind]
    cve_ids = ";".join(_norm_ids(a.get("identifiers"), "CVE"))
    other_ids = ";".join(
        f"{i.get('type')}:{i.get('value')}"
        for i in (a.get("identifiers") or [])
        if i.get("type") != "CVE"
    )
    cwes = ";".join(
        f"{c.get('cwe_id','')} {c.get('name','')}".strip()
        for c in (a.get("cwes") or [])
    )

    # accept list OR object OR missing
    epss_raw = a.get("epss")
    epss_pct = None
    epss_prc = None
    if isinstance(epss_raw, list) and epss_raw:
        first = epss_raw[0] or {}
        epss_pct = first.get("percentage")
        epss_prc = first.get("percentile")
    elif isinstance(epss_raw, dict):
        epss_pct = epss_raw.get("percentage")
        epss_prc = epss_raw.get("percentile")

    # Vulnerabilities
    vulns = a.get("vulnerabilities") or []
    if not isinstance(vulns, list):
        vulns = []

    for v in vulns:
        pkg = (v.get("package") or {})
        rows.append({
            "ghsa_id": ghsa_id,
            "severity": severity,
            "summary": summary,
            "html_url": html_url,
            "published_at": published_at,
            "updated_at": updated_at,
            "withdrawn_at": withdrawn_at,
            "github_reviewed_at": github_reviewed_at,
            "nvd_published_at": nvd_published_at,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cve_ids": cve_ids,
            "other_identifiers": other_ids,
            "cwes": cwes,
            "epss_percentage": epss_pct,
            "epss_percentile": epss_prc,
            "package_name": pkg.get("name"),
            "ecosystem": pkg.get("ecosystem"),
            "vulnerable_version_range": v.get("vulnerable_version_range"),
            "first_patched_version": v.get("first_patched_version"),
            "vulnerable_functions": ";".join(v.get("vulnerable_functions") or []),
        })

    # Some advisories might not have 'vulnerabilities'
    if not vulns:
        rows.append({
            "ghsa_id": ghsa_id,
            "severity": severity,
            "summary": summary,
            "html_url": html_url,
            "published_at": published_at,
            "updated_at": updated_at,
            "withdrawn_at": withdrawn_at,
            "github_reviewed_at": github_reviewed_at,
            "nvd_published_at": nvd_published_at,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cve_ids": cve_ids,
            "other_identifiers": other_ids,
            "cwes": cwes,
            "epss_percentage": epss_pct,
            "epss_percentile": epss_prc,
            "package_name": None,
            "ecosystem": None,
            "vulnerable_version_range": None,
            "first_patched_version": None,
            "vulnerable_functions": None,
        })

    return rows

def write_csv(csv_path: Path, rows: List[Dict[str, Any]]):
    fieldnames = [
        "ghsa_id", "severity", "summary", "html_url",
        "published_at", "updated_at", "withdrawn_at",
        "github_reviewed_at", "nvd_published_at",
        "cvss_score", "cvss_vector", "cve_ids", "other_identifiers", "cwes",
        "epss_percentage", "epss_percentile",
        "package_name", "ecosystem", "vulnerable_version_range", "first_patched_version",
        "vulnerable_functions",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

# ------------------------- paging -------------------------

def fetch_all_advisories(api_base: str, token: str, query_params: dict):
    """Generator over ALL advisories, following Link: rel=next."""
    url = f"{api_base.rstrip('/')}/advisories"
    next_url = url
    next_params = query_params
    page = 0
    while next_url:
        page += 1
        r = rest_get(next_url, token, params=next_params)
        advisories = r.json()
        print(f"[*] page {page}: {len(advisories)} advisories", file=sys.stderr)
        for a in advisories:
            yield a
        # Follow Link header if present
        links = r.links or {}
        next_link = links.get("next", {})
        next_url = next_link.get("url")
        next_params = None  # URL already contains the cursor/query string

# ------------------------- main -------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Download GitHub Advisory Database via REST, zip advisories by severity, and generate a vulnerabilities CSV."
    )
    ap.add_argument("--out", required=True, help="Output directory (created if missing)")
    ap.add_argument("--token", help="GitHub token (overrides GITHUB_TOKEN)")
    ap.add_argument("--api-base", default=API_BASE_DEFAULT, help="REST API base (default: https://api.github.com)")
    ap.add_argument("--per-page", type=int, default=100, help="Results per page (max 100)")
    ap.add_argument("--sleep", type=float, default=0.0, help="Optional per-advisory sleep (seconds)")
    # Server-side filters (comma-separated lists are supported by the REST API)
    ap.add_argument("--severity", help="Filter: unknown,low,medium,high,critical (comma-separated OK)")
    ap.add_argument("--ecosystem", help="Filter: npm,pip,maven,nuget,go,rubygems,composer,rust,erlang,actions,pub,other,swift (comma-separated OK)")
    ap.add_argument("--sort", default="updated", choices=["updated", "published"], help="Sort field (default: updated)")
    ap.add_argument("--direction", default="asc", choices=["asc", "desc"], help="Sort direction (default: asc)")
    args = ap.parse_args()

    token = args.token or os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise SystemExit("No token provided. Use --token ghp_... or set GITHUB_TOKEN.")

    # Fail fast with a simple REST self-test
    verify_token_rest(args.api_base, token)

    base_out = Path(args.out).resolve()
    base_out.mkdir(parents=True, exist_ok=True)
    dirs = ensure_dirs(base_out)
    sev_dir_map = {sev: dirs[sev] for sev in SEVERITY_ORDER}

    # Build query params for server-side filtering & pagination
    params = {
        "per_page": max(1, min(100, args.per_page)),
        "sort": args.sort,
        "direction": args.direction,
    }
    if args.severity:
        params["severity"] = args.severity
    if args.ecosystem:
        params["ecosystem"] = args.ecosystem

    all_rows: List[Dict[str, Any]] = []
    total = 0

    # Walk all advisories (each already includes vulnerabilities)
    for advisory in fetch_all_advisories(args.api_base, token, params):
        sev_raw = (advisory.get("severity") or "low").lower()
        sev_bucket = SEV_MAP.get(sev_raw, "low")
        write_advisory_json(advisory, sev_dir_map[sev_bucket])
        all_rows.extend(build_csv_rows_from_advisory(advisory))
        total += 1
        if args.sleep > 0:
            time.sleep(args.sleep)

    csv_path = base_out / "vulnerabilities.csv"
    write_csv(csv_path, all_rows)
    print(f"[csv] wrote {csv_path} with {len(all_rows)} rows from {total} advisories", file=sys.stderr)

    zip_by_severity(sev_dir_map, dirs["zips_base"])
    print("[*] Done.", file=sys.stderr)

if __name__ == "__main__":
    main()
