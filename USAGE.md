# Usage Guide (Kali Linux / Debian)

## 1) System Preparation

Update package indexes:

```bash
sudo apt-get update
```

Install core utilities:

```bash
sudo apt-get install -y git curl jq unzip python3 python3-pip
```

## 2) Azure CLI Installation Notes (Kali/Debian)

On Debian-based systems, install Azure CLI using Microsoft's official package feed. Kali may require extra care if package sources are customized.

Typical installation pattern:

```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

Verify:

```bash
az version
```

If Azure CLI package installation fails on Kali, see troubleshooting below.

## 3) Optional Tools

### Prowler (Docker-based expected path)
Install Docker and verify daemon access if you want integrated Prowler runs.

### ScoutSuite
Install via pip:

```bash
pip3 install scoutsuite
```

## 4) Service Principal Authentication Workflow

The script prompts for:
- Client name
- Tenant ID
- App (client) ID
- Client secret
- Subscription IDs

It then authenticates non-interactively with Azure CLI using service principal credentials and validates subscription access before module execution.

## 5) Required Access Model

### Azure roles
- Reader (each in-scope subscription)
- Security Reader (each in-scope subscription)
- Global Reader (Entra ID)

### Graph API permissions
- User.Read.All
- Policy.Read.All
- Directory.Read.All
- AuditLog.Read.All
- RoleManagement.Read.All

Admin consent must be granted where required.

## 6) Run the Tool

```bash
chmod +x azure-cloud-config-review.sh
./azure-cloud-config-review.sh
```

## 7) Prompts You Will See

You should expect interactive prompts for scope and credential details. During runtime, module progress, findings severities, and integration status messages are displayed.

## 8) What to Expect During Execution

- Dependency checks
- Azure authentication checks
- Multi-module data collection and control checks
- Optional Prowler/ScoutSuite execution when available
- Findings and report assembly

## 9) Reading the HTML Report

The HTML report includes:
- Severity summary metrics
- Findings table with modules/techniques
- Extracted resource references and deep links (where available)
- Threat model summary sections

## 10) Output Locations

Outputs are written to the assessment run directory (for example `azure-review_YYYYMMDD_HHMMSS/`) including module folders and `reports/` content.

## Troubleshooting

### `az: command not found`
- Confirm Azure CLI installed successfully.
- Ensure `/usr/bin` (or Azure CLI install path) is in `PATH`.
- Open a new shell and run `az version`.

### Azure CLI install failure on Kali
- Verify apt sources are not broken.
- Run `sudo apt-get update --fix-missing`.
- Re-run the official install script.
- If organizational hardening blocks package install, use an approved prebuilt assessment host.

### Service principal login failure
- Re-check tenant ID, app ID, and client secret.
- Confirm secret is unexpired and not revoked.
- Confirm service principal is enabled.

### Missing subscription access
- Validate each subscription ID is correct.
- Ensure Reader + Security Reader are granted to the service principal on every in-scope subscription.

### Graph API permission errors
- Confirm required Graph application permissions are assigned.
- Confirm tenant admin consent has been granted.
- Re-test Graph calls with `az rest` using the same principal.

### Docker/Prowler not available
- Install Docker and verify `docker ps` works.
- If unavailable, continue without Prowler outputs and document limitation in assessment notes.

### ScoutSuite not available
- Install with `pip3 install scoutsuite`.
- Confirm executable availability (`scout --help` or package entrypoint in your environment).

### HTML report generation failure
- Verify Python 3 is installed.
- Confirm `azure_html_report_generator.py` exists and is executable/readable.
- Check for malformed findings logs or missing expected report input files.
