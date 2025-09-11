# GitHub Advisory Database Export using REST

`crogl_rest.py` pulls **all Global Security Advisories** from the **GitHub Advisory Database** via the **REST API**, saves each advisory as JSON grouped by **severity**, builds **four ZIPs** (`low`, `moderate`, `high`, `critical`), and generates a **CSV** with **one row per vulnerability** plus key metadata.

- Uses standard REST pagination (follows `Link: rel="next"`).
- Handles rate limits (waits until reset if needed).
- Robust to field shape differences (e.g., EPSS present/absent/object/list).

❗️Security note: This script requires a **Personal Access Token (classic)** (starts with `ghp_…`). 

---

## Requirements

- **Python 3.9+**
- Python package: `requests`

---

## Quick Start

### 1) Create a GitHub **Personal Access Token (classic)**
- GitHub → Settings → Developer settings → **Personal access tokens (classic)** → Generate new token.  
- No special scopes required for public advisories.  
- If your org enforces SAML SSO, open the token page and click **Authorize** for your org.

### 2) Run the script

#### Linux / macOS (bash/zsh)
```bash
export GITHUB_TOKEN=<your_taken_copied_from_git>
python3 crogl_rest_udated.py --out ./<your_output_folder_name> Ex:ghp_************************************
```

#### Windows (PowerShell)
```powershell
$env:GITHUB_TOKEN="<your_taken_copied_from_git>"
python crogl_rest_udated.py --out ".\<your_output_folder_name>" Ex:ghp_************************************
```

#### Windows (CMD)
```cmd
set GITHUB_TOKEN=<your_taken_copied_from_git>
python crogl_rest_udated.py --out .\<your_output_folder_name> Ex:ghp_************************************
```

### Output
```
ghsa_rest_export/
  advisories/
    low/*.json
    moderate/*.json
    high/*.json
    critical/*.json
  zips/
    advisories_low.zip
    advisories_moderate.zip
    advisories_high.zip
    advisories_critical.zip
  vulnerabilities.csv
```

REST returns severities `unknown | low | medium | high | critical`.  
This script maps **`medium → moderate`** and **`unknown → low`** to produce the four buckets.

---

## Usage & Options

```
python crogl_rest_udated.py --out <DIR> [options]
```

**Required**
- `--out PATH`               Output directory (created if missing)

**Auth**
- `--token TOKEN`            Token (overrides `GITHUB_TOKEN` env var)
- `GITHUB_TOKEN`             Env var with your classic PAT (recommended)

**API Host (GitHub Enterprise Server)**
- `--api-base URL`           REST base (default `https://api.github.com`)
  - GHES example: `https://<your-ghes-host>/api/v3`

**Pagination & Pacing**
- `--per-page N`             Items per page (max 100, default 100)
- `--sleep SECONDS`          Optional delay after processing each advisory
- `GHSARL_MIN_INTERVAL=0.3`  (env) Minimum seconds between HTTP requests (helps avoid secondary rate limits)

**Filtering & Ordering**
- `--severity s1,s2,…`       Filter by severity (e.g., `high,critical`)
- `--ecosystem e1,e2,…`      Filter by ecosystem (e.g., `npm,pip,maven,nuget,go,rubygems,composer,rust,erlang,actions,pub,other,swift`)
- `--sort [updated|published]`  Sort field (default `updated`)
- `--direction [asc|desc]`      Sort direction (default `asc`)

### Examples

Only **high/critical** advisories, newest first:
```bash
export GITHUB_TOKEN=ghp_...
python3 crogl_rest_udated.py --out ./export_high_critical \
  --severity high,critical --sort updated --direction desc
```

Only **npm** ecosystem:
```bash
export GITHUB_TOKEN=ghp_...
python3 crogl_rest_udated.py --out ./export_npm --ecosystem npm
```

GitHub Enterprise Server (GHES):
```bash
python3 crogl_rest_udated.py --out ./export_ghes \
  --api-base https://github.company.com/api/v3 \
  --token ghp_...
```

Throttle requests (helpful behind corporate networks / CI):
```bash
export GHSARL_MIN_INTERVAL=0.5
python3 crogl_rest_udated.py --out ./export
```

---

## CSV Schema

`vulnerabilities.csv` includes one row per vulnerability (package/ecosystem/version range) with advisory metadata:

- `ghsa_id`
- `severity` (low | moderate | high | critical)
- `summary`
- `html_url`
- `published_at`, `updated_at`, `withdrawn_at`, `github_reviewed_at`, `nvd_published_at`
- `cvss_score`, `cvss_vector` (falls back to CVSS v4/v3 if `cvss` absent)
- `cve_ids`, `other_identifiers`, `cwes`
- `epss_percentage`, `epss_percentile` (if present)
- `package_name`, `ecosystem`
- `vulnerable_version_range`, `first_patched_version`
- `vulnerable_functions` (if present)

---

## Verifying Your Token

Before first run, test the token quickly:

**Linux / macOS**
```bash
curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user
```

**Windows PowerShell**
```powershell
curl.exe -s -H "Authorization: Bearer $env:GITHUB_TOKEN" https://api.github.com/user
```

You should see your GitHub login in the JSON. If you see `"message": "Bad credentials"`, fix your token (see below).

---

## Common Problems & Fixes

### 1) `401 Unauthorized` / “Bad credentials”
- Create a **Personal Access Token (classic)** (`ghp_…`), not fine-grained.
- If your org enforces SAML SSO, open the token page and click **Authorize** for your org.
- Paste the **raw** token (no `Bearer`, no quotes, no trailing spaces/newlines).
- Re-test with `curl` (see **Verifying Your Token**).

### 2) `403` / `429` Rate limit exceeded
- The script waits for reset when GitHub signals limits.
- Slow down proactively:
  ```bash
  export GHSARL_MIN_INTERVAL=0.3
  ```
- Reduce `--per-page` (e.g., `--per-page 50`) or run after a short pause.

### 3) `404 Not Found` (esp. on Enterprise)
- For **GHES**, set `--api-base https://<your-ghes-host>/api/v3`.

### 4) Windows quoting / env vars
- PowerShell: `$env:GITHUB_TOKEN="ghp_..."` (double quotes are fine).
- CMD: `set GITHUB_TOKEN=ghp_...` (no quotes).

### 5) SSL/TLS or proxy issues
- If behind a proxy/firewall, set:
  ```bash
  export HTTPS_PROXY=http://proxy.example.com:8080
  export HTTP_PROXY=http://proxy.example.com:8080
  ```
- Ensure your corporate root CA is trusted by Python.

### 6) File permissions / disk space
- Ensure the `--out` directory is writable and has space for thousands of JSON files and ZIPs.

### 7) Hidden newline in token
- Save without newline:
  ```bash
  printf '%s' 'ghp_yourCLASSICtoken' > token.txt
  export GITHUB_TOKEN="$(cat token.txt)"
  ```

---

## Security Tips

- Prefer **env vars** over command-line flags (flags can appear in shell history / process list).
- Never commit your token or `token.txt` to git.
- Revoke tokens you accidentally exposed.

---

## Severity Bucketing

GitHub REST returns: `unknown | low | medium | high | critical`.  
This script maps:
- `medium` → **`moderate`**
- `unknown` → **`low`**

so you get four output folders and ZIPs: `low`, `moderate`, `high`, `critical`.

---

## Exit Codes & Logging

- Progress is printed to **stderr** (page counts, rate-limit waits, zip summaries).
- The script exits non-zero on fatal errors (bad token, repeated network failures).

---

## License

Use and modify freely. If you improve the script (new filters, columns, etc.), please consider contributing back your changes.

# Crogl
