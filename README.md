# Azure Cloud Configuration Review

Azure Cloud Configuration Review is an internal security assessment tool used by authorized consultants to evaluate Azure tenant and subscription security posture during approved cloud security reviews and penetration testing engagements.

It combines automated Azure/Entra data collection, control validation, threat-model-oriented checks, third-party tool ingestion, and consolidated HTML reporting.

## Framework Alignment

This review process is mapped to commonly used security frameworks and guidance:

- **CSA Cloud Controls Matrix (CCM)**
- **CIS Microsoft Azure Foundations Benchmark**
- **MITRE ATT&CK for Cloud**
- **Azure Well-Architected Framework — Security Pillar**

## Major Capabilities

- Posture review
- Logistics / inventory collection
- Visibility audit
- Access verification
- Trust verification
- Controls verification
- Threat modeling outputs
- Prowler integration (if available)
- ScoutSuite integration (if available)
- HTML report generation for delivery-ready findings summaries

## Required Azure Permissions

### Azure Role Assignments (in-scope environment)
- **Reader** on each in-scope subscription
- **Security Reader** on each in-scope subscription
- **Global Reader** in Microsoft Entra ID

### Microsoft Graph API Application Permissions
- `User.Read.All`
- `Policy.Read.All`
- `Directory.Read.All`
- `AuditLog.Read.All`
- `RoleManagement.Read.All`

## Prerequisites

See [REQUIREMENTS.md](REQUIREMENTS.md) for required and optional dependencies.

## Quick Start

1. Install dependencies (Azure CLI, Python 3, jq, etc.).
2. Ensure service principal permissions are granted and consented.
3. Run:

```bash
chmod +x azure-cloud-config-review.sh
./azure-cloud-config-review.sh
```

4. Follow prompts for:
   - Client name
   - Tenant ID
   - Service principal App (client) ID
   - Service principal client secret
   - Comma-separated subscription IDs

5. Review generated outputs and HTML report in the run folder.

## Output Folder Overview

Each run creates a timestamped assessment folder (for example: `azure-review_YYYYMMDD_HHMMSS/`) with module output directories and a `reports/` folder containing findings summaries and HTML report artifacts.

## Example Run Flow

1. Dependency and environment checks
2. Service principal authentication and scope validation
3. Six review modules execute across in-scope subscriptions/tenant
4. Optional Prowler/ScoutSuite collection runs if tooling is available
5. Findings are normalized and rendered to HTML

## Authorized-Use Disclaimer

This tool is **strictly for authorized Azure Cloud Configuration Reviews** and approved security testing engagements. Do not execute against any environment without documented written authorization.

For operational instructions and troubleshooting, see [USAGE.md](USAGE.md).
