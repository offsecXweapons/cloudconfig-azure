#!/usr/bin/env python3
"""
Azure Cloud Configuration Review — HTML Report Generator v1.0
Produces a self-contained HTML report with:
  - Azure resource ID extraction from finding messages
  - Azure Portal deep-links per resource
  - Dedicated Resource column in findings table
  - Resource Inventory tab
  - Filterable/searchable findings
  - Threat model cards
  - Framework coverage bars
"""
import sys, os, html as _html, glob, re
from datetime import datetime

# ── Azure Resource Pattern Extraction ─────────────────────────────────────────
# ARM resource ID pattern (full paths like /subscriptions/.../providers/...)
ARM_ID_RE = re.compile(
    r'(/subscriptions/[0-9a-f-]{36}/resourceGroups/[^/\s]+/providers/[^\s\'"]+)',
    re.IGNORECASE
)

RESOURCE_PATTERNS = [
    # Subscription GUIDs
    (re.compile(r'\bSub(?:scription)?[=:\s]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b', re.IGNORECASE), 'subscription'),
    # Full ARM IDs
    (ARM_ID_RE, 'arm-resource'),
    # Named resource patterns
    (re.compile(r"Storage account '([^']+)'",       re.IGNORECASE), 'storage-account'),
    (re.compile(r"storage account '([^']+)'",        re.IGNORECASE), 'storage-account'),
    (re.compile(r"SA=([^\s|]+)",                     re.IGNORECASE), 'storage-account'),
    (re.compile(r"VM '([^']+)'",                     re.IGNORECASE), 'virtual-machine'),
    (re.compile(r"VM=([^\s|]+)",                     re.IGNORECASE), 'virtual-machine'),
    (re.compile(r"NSG '([^']+)'",                    re.IGNORECASE), 'network-security-group'),
    (re.compile(r"NSG=([^\s|]+)",                    re.IGNORECASE), 'network-security-group'),
    (re.compile(r"Key Vault '([^']+)'",              re.IGNORECASE), 'key-vault'),
    (re.compile(r"Key Vault=([^\s|]+)",              re.IGNORECASE), 'key-vault'),
    (re.compile(r"SQL Server '([^']+)'",             re.IGNORECASE), 'sql-server'),
    (re.compile(r"SQL Server=([^\s|]+)",             re.IGNORECASE), 'sql-server'),
    (re.compile(r"PostgreSQL Server '([^']+)'",      re.IGNORECASE), 'postgresql-server'),
    (re.compile(r"MySQL Server '([^']+)'",           re.IGNORECASE), 'mysql-server'),
    (re.compile(r"Function App '([^']+)'",           re.IGNORECASE), 'function-app'),
    (re.compile(r"FunctionApp=([^\s|]+)",            re.IGNORECASE), 'function-app'),
    (re.compile(r"App Service '([^']+)'",            re.IGNORECASE), 'app-service'),
    (re.compile(r"AKS cluster '([^']+)'",            re.IGNORECASE), 'aks-cluster'),
    (re.compile(r"AKS=([^\s|]+)",                    re.IGNORECASE), 'aks-cluster'),
    (re.compile(r"Application Gateway '([^']+)'",    re.IGNORECASE), 'application-gateway'),
    (re.compile(r"AppGW=([^\s|]+)",                  re.IGNORECASE), 'application-gateway'),
    (re.compile(r"Load Balancer '([^']+)'",          re.IGNORECASE), 'load-balancer'),
    (re.compile(r"LB=([^\s|]+)",                     re.IGNORECASE), 'load-balancer'),
    (re.compile(r"APIM '([^']+)'",                   re.IGNORECASE), 'api-management'),
    (re.compile(r"APIM=([^\s|]+)",                   re.IGNORECASE), 'api-management'),
    (re.compile(r"Snapshot '([^']+)'",               re.IGNORECASE), 'disk-snapshot'),
    (re.compile(r"user '([^']+)'",                   re.IGNORECASE), 'entra-user'),
    (re.compile(r"SP '([^']+)'",                     re.IGNORECASE), 'service-principal'),
    (re.compile(r"service principal '([^']+)'",      re.IGNORECASE), 'service-principal'),
    (re.compile(r"VNet '([^']+)'",                   re.IGNORECASE), 'virtual-network'),
    (re.compile(r"VNet=([^\s|]+)",                   re.IGNORECASE), 'virtual-network'),
    (re.compile(r"Gallery '([^']+)'",                re.IGNORECASE), 'image-gallery'),
    # Subscription IDs (plain UUID format)
    (re.compile(r'\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b', re.IGNORECASE), 'subscription'),
]

# ── Azure Portal URL Builders ──────────────────────────────────────────────────
PORTAL_BASE = "https://portal.azure.com"

def portal_url(resource_type: str, resource_id: str, sub_id: str = '') -> str:
    """Build Azure Portal deep-link for a given resource type and identifier."""
    browse = f"{PORTAL_BASE}/#browse"
    blade  = f"{PORTAL_BASE}/#resource"

    # If it's a full ARM ID, build a direct resource blade link
    if resource_type == 'arm-resource' and resource_id.startswith('/subscriptions/'):
        return f"{blade}{resource_id}"

    urls = {
        'storage-account':       f"{browse}/Microsoft.Storage%2FstorageAccounts",
        'virtual-machine':       f"{browse}/Microsoft.Compute%2FvirtualMachines",
        'network-security-group':f"{browse}/Microsoft.Network%2FnetworkSecurityGroups",
        'key-vault':             f"{browse}/Microsoft.KeyVault%2Fvaults",
        'sql-server':            f"{browse}/Microsoft.Sql%2Fservers",
        'postgresql-server':     f"{browse}/Microsoft.DBforPostgreSQL%2Fservers",
        'mysql-server':          f"{browse}/Microsoft.DBforMySQL%2Fservers",
        'function-app':          f"{browse}/Microsoft.Web%2Fsites",
        'app-service':           f"{browse}/Microsoft.Web%2Fsites",
        'aks-cluster':           f"{browse}/Microsoft.ContainerService%2FmanagedClusters",
        'application-gateway':   f"{browse}/Microsoft.Network%2FapplicationGateways",
        'load-balancer':         f"{browse}/Microsoft.Network%2FloadBalancers",
        'api-management':        f"{browse}/Microsoft.ApiManagement%2Fservice",
        'disk-snapshot':         f"{browse}/Microsoft.Compute%2Fsnapshots",
        'virtual-network':       f"{browse}/Microsoft.Network%2FvirtualNetworks",
        'image-gallery':         f"{browse}/Microsoft.Compute%2Fgalleries",
        'entra-user':            f"{PORTAL_BASE}/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview",
        'service-principal':     f"{PORTAL_BASE}/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview",
        'subscription':          f"{PORTAL_BASE}/#@/resource/subscriptions/{resource_id}" if resource_id else
                                 f"{browse}/Microsoft.Resources%2Fsubscriptions",
    }
    return urls.get(resource_type, '')


def extract_resources(message: str):
    """Extract Azure resource identifiers from a finding message."""
    found = []
    seen  = set()

    # Extract subscription ID from context (e.g. "Sub: 00000000-...")
    sub_match = re.search(r'Sub(?:scription)?[=:\s]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', message, re.IGNORECASE)
    sub_id = sub_match.group(1) if sub_match else ''

    for pattern, rtype in RESOURCE_PATTERNS:
        for m in pattern.finditer(message):
            rid = m.group(1)
            # Skip bare UUIDs that are the subscription ID already extracted
            if rtype == 'subscription' and rid == sub_id and sub_id in seen:
                continue
            if rid not in seen:
                seen.add(rid)
                url = portal_url(rtype, rid, sub_id)
                found.append((rid, rtype, url, sub_id))
    return found, sub_id


def resource_badges(resources) -> str:
    """Build HTML badge links for extracted Azure resources."""
    if not resources:
        return '<span style="color:#9ca3af;font-size:11px">—</span>'
    parts = []
    for rid, rtype, url, sub_id in resources[:4]:
        label      = rid[:36] + '…' if len(rid) > 36 else rid
        type_label = rtype.replace('-', ' ').upper()
        if url:
            parts.append(
                f'<a href="{_html.escape(url)}" target="_blank" '
                f'title="{_html.escape(type_label)}: {_html.escape(rid)}" '
                f'style="display:inline-block;margin:1px 2px;padding:2px 7px;background:#eff6ff;'
                f'color:#1d4ed8;border:1px solid #bfdbfe;border-radius:4px;font-size:11px;'
                f'text-decoration:none;white-space:nowrap;font-family:monospace">'
                f'{_html.escape(label)} ↗</a>'
            )
        else:
            parts.append(
                f'<span title="{_html.escape(type_label)}" '
                f'style="display:inline-block;margin:1px 2px;padding:2px 7px;background:#f1f5f9;'
                f'color:#475569;border:1px solid #e2e8f0;border-radius:4px;font-size:11px;'
                f'font-family:monospace">{_html.escape(label)}</span>'
            )
    if len(resources) > 4:
        parts.append(
            f'<span style="font-size:10px;color:#9ca3af">+{len(resources)-4} more</span>'
        )
    return ''.join(parts)


# ── Load resource inventory sections ──────────────────────────────────────────
def load_inventory(output_dir: str):
    inv_file = os.path.join(output_dir, 'reports', 'resource-inventory.txt')
    if not os.path.exists(inv_file):
        return []
    sections      = []
    current_title = None
    current_lines = []
    with open(inv_file) as f:
        for line in f:
            line = line.rstrip()
            if line.startswith('──'):
                if current_title and current_lines:
                    sections.append((current_title,
                                     [l for l in current_lines if l.strip()]))
                current_title = line.strip('─ \t')
                current_lines = []
            elif line.startswith('===') or 'END OF' in line:
                continue
            elif current_title is not None:
                current_lines.append(line)
    if current_title and current_lines:
        sections.append((current_title,
                         [l for l in current_lines if l.strip()]))
    return sections


def main():
    args         = sys.argv[1:]
    output_dir   = args[0]
    client       = args[1]
    tenant_id    = args[2]
    app_id       = args[3]
    version      = args[4]
    findings_c   = int(args[5] or 0)
    findings_h   = int(args[6] or 0)
    findings_m   = int(args[7] or 0)
    findings_i   = int(args[8] or 0)
    date_run     = args[9] if len(args) > 9 else datetime.now().strftime('%Y-%m-%d %H:%M')
    sub_list     = args[10] if len(args) > 10 else ''

    def esc(s): return _html.escape(str(s))

    # ── Load findings log ──────────────────────────────────────────────────
    findings = []
    flog = os.path.join(output_dir, 'reports', 'findings.log')
    if os.path.exists(flog):
        with open(flog) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('SEVERITY'):
                    continue
                parts = line.split('|', 4)
                if len(parts) >= 4:
                    msg       = parts[3].strip()
                    resources, sub_id = extract_resources(msg)
                    findings.append({
                        'severity':  parts[0].strip(),
                        'module':    parts[1].strip(),
                        'technique': parts[2].strip(),
                        'message':   msg,
                        'time':      parts[4].strip() if len(parts) > 4 else '',
                        'resources': resources,
                        'sub_id':    sub_id,
                    })

    # ── Load threat models ─────────────────────────────────────────────────
    threat_models = []
    tmf = os.path.join(output_dir, 'reports', 'threat-models.txt')
    if os.path.exists(tmf):
        current = {}
        with open(tmf) as f:
            for line in f:
                line = line.rstrip()
                if line.startswith('=== THREAT MODEL'):
                    if current:
                        threat_models.append(current)
                    current = {'title': line.strip('= '), 'risk': 'LOW',
                               'chain': '', 'narrative': ''}
                elif line.startswith('Risk:') and current:
                    current['risk'] = line.split('|')[0].replace('Risk:', '').strip()
                elif line.startswith('MITRE Chain:') and current:
                    current['chain'] = line.replace('MITRE Chain:', '').strip()
                elif line.startswith('Narrative:') and current:
                    current['narrative'] = line.replace('Narrative:', '').strip()
        if current:
            threat_models.append(current)

    # ── Load resource inventory ────────────────────────────────────────────
    inv_sections   = load_inventory(output_dir)
    total_findings = len(findings)

    # ── Helpers ────────────────────────────────────────────────────────────
    def sev_class(s):
        return {
            'CRITICAL': 'sev-critical',
            'HIGH':     'sev-high',
            'MEDIUM':   'sev-medium',
            'INFO':     'sev-info',
        }.get(s.upper(), 'sev-info')

    def risk_badge_html(r):
        colors = {
            'CRITICAL': '#dc2626',
            'HIGH':     '#ea580c',
            'MEDIUM':   '#ca8a04',
            'LOW':      '#16a34a',
        }
        c = colors.get(r.upper(), '#6b7280')
        return (f'<span style="background:{c};color:#fff;padding:3px 12px;'
                f'border-radius:12px;font-size:12px;font-weight:700">{esc(r)}</span>')

    def coverage_bar(label, pct, color):
        return (
            f'<div class="fw-row">'
            f'<div class="fw-label">{esc(label)}</div>'
            f'<div class="fw-bar-bg"><div class="fw-bar" '
            f'style="width:{pct}%;background:{color}"></div></div>'
            f'<div class="fw-pct">{pct}%</div></div>'
        )

    def tool_card(name, icon, path_glob, color):
        files  = glob.glob(os.path.join(output_dir, path_glob))
        status = 'Available' if files else 'No output'
        st_col = '#16a34a' if files else '#9ca3af'
        fp     = files[0] if files else ''
        link   = (f'<a href="file://{esc(fp)}" target="_blank" '
                  f'style="color:{color};font-size:12px">Open →</a>'
                  if fp else '')
        return (
            f'<div class="tool-card">'
            f'<div style="font-size:26px">{icon}</div>'
            f'<div class="tool-name">{esc(name)}</div>'
            f'<div style="color:{st_col};font-size:12px;margin:4px 0">{status}</div>'
            f'{link}</div>'
        )

    # ── Framework coverage bars ────────────────────────────────────────────
    total = total_findings or 1
    crit_high = findings_c + findings_h
    fw_pct_csa   = min(100, max(30, int(100 - (crit_high / total * 40))))
    fw_pct_cis   = min(100, max(30, int(100 - (findings_c / total * 50))))
    fw_pct_mitre = min(100, max(30, int(100 - (crit_high / total * 30))))
    fw_pct_waf   = min(100, max(35, int(100 - (findings_h / total * 35))))

    fw_bars = (
        coverage_bar('CSA Cloud Controls Matrix',               fw_pct_csa,   '#2563eb') +
        coverage_bar('CIS Azure Benchmark',                     fw_pct_cis,   '#7c3aed') +
        coverage_bar('MITRE ATT&CK for Cloud',                  fw_pct_mitre, '#dc2626') +
        coverage_bar('Azure Well-Architected Security Pillar',  fw_pct_waf,   '#059669')
    )

    # ── Tool cards ─────────────────────────────────────────────────────────
    tool_cards = (
        tool_card('Prowler (Azure)',  '🔍', '07-tool-output/prowler/*.html',   '#2563eb') +
        tool_card('ScoutSuite',       '🏕️',  '07-tool-output/scoutsuite/*.html','#7c3aed') +
        tool_card('Prowler CSV',      '📊', '07-tool-output/prowler/*.csv',    '#059669')
    )

    # ── Build findings rows ────────────────────────────────────────────────
    rows_html = ''
    for f in findings:
        sc       = sev_class(f['severity'])
        tech     = (f'<code style="font-size:10px;background:#f1f5f9;padding:1px 5px;'
                    f'border-radius:3px">{esc(f["technique"])}</code>'
                    if f['technique'] else '—')
        res_html = resource_badges(f['resources'])
        res_ids  = ' '.join(r[0] for r in f['resources'])
        rows_html += (
            f'<tr class="finding-row {sc}" data-severity="{esc(f["severity"].upper())}" '
            f'data-resources="{esc(res_ids)}">'
            f'<td><span class="badge {sc}">{esc(f["severity"])}</span></td>'
            f'<td style="font-size:11px;color:#6b7280;white-space:nowrap">{esc(f["module"])}</td>'
            f'<td>{tech}</td>'
            f'<td style="word-break:break-word;font-size:13px">{esc(f["message"])}</td>'
            f'<td>{res_html}</td>'
            f'<td style="font-size:11px;color:#9ca3af;white-space:nowrap">{esc(f["time"])}</td>'
            f'</tr>'
        )

    # ── Build remediation rows (Critical + High only) ──────────────────────
    remed_rows = ''
    for f in findings:
        if f['severity'].upper() not in ('CRITICAL', 'HIGH'):
            continue
        sc       = sev_class(f['severity'])
        res_html = resource_badges(f['resources'])
        tech     = (f'<code style="font-size:10px;background:#f1f5f9;padding:1px 5px;'
                    f'border-radius:3px">{esc(f["technique"])}</code>'
                    if f['technique'] else '—')
        remed_rows += (
            f'<tr class="finding-row {sc}">'
            f'<td><span class="badge {sc}">{esc(f["severity"])}</span></td>'
            f'<td style="word-break:break-word;font-size:13px">{esc(f["message"])}</td>'
            f'<td>{res_html}</td>'
            f'<td>{tech}</td>'
            f'</tr>'
        )

    # ── Build threat model cards ───────────────────────────────────────────
    tm_cards = ''
    for tm in threat_models:
        badge       = risk_badge_html(tm['risk'])
        risk_border = {
            'CRITICAL': '#dc2626', 'HIGH': '#ea580c',
            'MEDIUM': '#ca8a04',   'LOW':  '#16a34a',
        }.get(tm['risk'].upper(), '#e2e8f0')
        tm_cards += (
            f'<div class="tm-card" style="border-left:4px solid {risk_border}">'
            f'<div class="tm-header">'
            f'<span class="tm-title">{esc(tm["title"])}</span>{badge}</div>'
            f'<div class="tm-chain"><strong>MITRE:</strong> '
            f'<code style="font-size:11px">{esc(tm["chain"])}</code></div>'
            f'<div class="tm-narrative">{esc(tm["narrative"])}</div>'
            f'</div>'
        )

    # ── Build resource inventory HTML ──────────────────────────────────────
    inv_html = ''
    if inv_sections:
        for title, lines in inv_sections:
            if not lines or (len(lines) == 1 and 'None found' in lines[0]):
                continue
            line_items = ''
            for line in lines:
                line = line.strip()
                if not line or '===' in line:
                    continue
                resources, sub_id = extract_resources(line)
                res_links = ''
                for rid, rtype, url, reg in resources[:2]:
                    if url:
                        res_links += (
                            f' <a href="{esc(url)}" target="_blank" '
                            f'style="font-size:10px;color:#2563eb;text-decoration:none;'
                            f'padding:1px 5px;background:#eff6ff;border-radius:3px;'
                            f'margin-left:4px">Portal ↗</a>'
                        )
                line_items += (
                    f'<div class="inv-row">'
                    f'<span style="font-family:monospace;font-size:12px;color:#1e293b">'
                    f'{esc(line)}</span>{res_links}</div>'
                )
            if line_items:
                inv_html += (
                    f'<div class="inv-section">'
                    f'<div class="inv-title">{esc(title)}</div>'
                    f'{line_items}</div>'
                )
    else:
        inv_html = ('<p style="color:#9ca3af;padding:20px">Resource inventory not available. '
                    'Run the script fully to generate inventory data.</p>')

    # ── CSS ────────────────────────────────────────────────────────────────
    CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f8fafc;color:#1e293b;font-size:14px}
header{background:linear-gradient(135deg,#0078d4 0%,#005a9e 50%,#003d6b 100%);color:#fff;padding:18px 28px;display:flex;justify-content:space-between;align-items:center;box-shadow:0 2px 8px rgba(0,0,0,.25)}
h1{font-size:22px;font-weight:700;letter-spacing:-.3px}
.sub{font-size:11px;color:rgba(255,255,255,.75);margin-top:3px}
.meta{text-align:right;font-size:12px;color:rgba(255,255,255,.8);line-height:1.7}
.tab-bar{background:#fff;border-bottom:2px solid #e2e8f0;padding:0 24px;display:flex;gap:0;position:sticky;top:0;z-index:100;box-shadow:0 1px 3px rgba(0,0,0,.07)}
.tab-btn{padding:14px 18px;border:none;background:none;cursor:pointer;font-size:13px;font-weight:500;color:#64748b;border-bottom:2px solid transparent;margin-bottom:-2px;transition:all .15s}
.tab-btn:hover{color:#0078d4;background:#f0f9ff}
.tab-btn.active{color:#0078d4;border-bottom-color:#0078d4;font-weight:700}
.container{max-width:1400px;margin:0 auto;padding:24px}
.tab-pane{display:none}.tab-pane.active{display:block}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.card{background:#fff;border-radius:10px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.num{font-size:38px;font-weight:800;line-height:1}
.lbl{font-size:12px;color:#64748b;margin-top:6px;font-weight:500}
.n-critical{color:#dc2626}.n-high{color:#ea580c}.n-medium{color:#ca8a04}.n-info{color:#2563eb}
.section{background:#fff;border-radius:10px;padding:20px;margin-bottom:20px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.section-title{font-size:15px;font-weight:700;color:#1e293b;margin-bottom:16px;padding-bottom:10px;border-bottom:2px solid #f1f5f9}
.fw-row{display:flex;align-items:center;gap:12px;margin:8px 0}
.fw-label{width:280px;font-size:12px;color:#475569;flex-shrink:0}
.fw-bar-bg{flex:1;height:10px;background:#f1f5f9;border-radius:5px;overflow:hidden}
.fw-bar{height:100%;border-radius:5px;transition:width .4s}
.fw-pct{width:36px;text-align:right;font-size:12px;font-weight:600;color:#64748b}
.filter-bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:12px;padding:10px;background:#f8fafc;border-radius:8px}
.filter-btn{padding:5px 12px;border:1px solid #e2e8f0;border-radius:20px;background:#fff;cursor:pointer;font-size:12px;font-weight:500;color:#64748b;transition:all .15s}
.filter-btn:hover{border-color:#0078d4;color:#0078d4}
.filter-btn.active{background:#0078d4;color:#fff;border-color:#0078d4}
.search-box{padding:6px 12px;border:1px solid #e2e8f0;border-radius:6px;font-size:12px;flex:1;min-width:220px;outline:none}
.search-box:focus{border-color:#0078d4;box-shadow:0 0 0 2px #dbeafe}
.table-wrap{width:100%}.scrollable{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{padding:10px 12px;text-align:left;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.4px;background:#f8fafc;border-bottom:2px solid #e2e8f0;white-space:nowrap}
td{padding:10px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top}
tr:hover td{background:#f8fafc}
.badge{display:inline-block;padding:3px 9px;border-radius:5px;font-size:11px;font-weight:700;white-space:nowrap}
.sev-critical .badge,.sev-critical.badge{background:#fef2f2;color:#991b1b;border:1px solid #fecaca}
.sev-high .badge,.sev-high.badge{background:#fff7ed;color:#9a3412;border:1px solid #fed7aa}
.sev-medium .badge,.sev-medium.badge{background:#fefce8;color:#854d0e;border:1px solid #fde68a}
.sev-info .badge,.sev-info.badge{background:#eff6ff;color:#1e40af;border:1px solid #bfdbfe}
.finding-row.hidden{display:none}
.tool-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.tool-card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px;text-align:center}
.tool-name{font-size:13px;font-weight:600;color:#1e293b;margin-top:6px}
.tm-card{background:#fff;border-radius:8px;padding:18px;margin-bottom:14px;border:1px solid #e2e8f0;box-shadow:0 1px 3px rgba(0,0,0,.05)}
.tm-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.tm-title{font-size:14px;font-weight:700;color:#1e293b}
.tm-chain{font-size:12px;color:#64748b;margin-bottom:8px}
.tm-narrative{font-size:13px;color:#475569;line-height:1.6}
.inv-section{margin-bottom:16px;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden}
.inv-title{background:#f0f9ff;padding:8px 14px;font-size:12px;font-weight:700;color:#0078d4;border-bottom:1px solid #bae6fd}
.inv-row{padding:6px 14px;border-bottom:1px solid #f8fafc;display:flex;align-items:center;justify-content:space-between}
.inv-row:last-child{border-bottom:none}
.inv-row:hover{background:#f8fafc}
@media(max-width:900px){.cards,.tool-grid{grid-template-columns:repeat(2,1fr)}}
"""

    # ── Assemble HTML document ─────────────────────────────────────────────
    subs_display = sub_list.replace(',', ' · ') if sub_list else 'N/A'
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Azure Cloud Config Review — {esc(client)}</title>
<style>{CSS}</style>
</head>
<body>

<header>
  <div>
    <h1>&#9729; Azure Cloud Configuration Review</h1>
    <div class="sub">CSA CCM &middot; CIS Azure Benchmark &middot; MITRE ATT&amp;CK for Cloud &middot; Azure Well-Architected Security Pillar</div>
  </div>
  <div class="meta">
    <div><strong style="color:#fff;font-size:15px">{esc(client)}</strong></div>
    <div>Tenant: {esc(tenant_id)}</div>
    <div>Assessor App: {esc(app_id)}</div>
    <div style="font-size:10px;max-width:350px;word-break:break-all">Subs: {esc(subs_display)}</div>
    <div>{esc(date_run)} &nbsp;|&nbsp; Script v{esc(version)}</div>
  </div>
</header>

<div class="tab-bar">
  <button class="tab-btn active" onclick="showTab('dashboard',this)">Dashboard</button>
  <button class="tab-btn" onclick="showTab('findings',this)">Findings ({total_findings})</button>
  <button class="tab-btn" onclick="showTab('resources',this)">Resource Inventory</button>
  <button class="tab-btn" onclick="showTab('remediation',this)">Remediation</button>
  <button class="tab-btn" onclick="showTab('threats',this)">Threat Models</button>
  <button class="tab-btn" onclick="showTab('tools',this)">Tool Output</button>
</div>

<div class="container">

<div id="tab-dashboard" class="tab-pane active">
  <div class="cards">
    <div class="card" style="border-top:3px solid #dc2626">
      <div class="num n-critical">{findings_c}</div><div class="lbl">&#128680; Critical</div></div>
    <div class="card" style="border-top:3px solid #ea580c">
      <div class="num n-high">{findings_h}</div><div class="lbl">&#9888; High</div></div>
    <div class="card" style="border-top:3px solid #ca8a04">
      <div class="num n-medium">{findings_m}</div><div class="lbl">&#9650; Medium</div></div>
    <div class="card" style="border-top:3px solid #2563eb">
      <div class="num n-info">{findings_i}</div><div class="lbl">&#8505; Info</div></div>
  </div>
  <div class="section">
    <div class="section-title">&#128202; Framework Coverage</div>
    {fw_bars}
  </div>
  <div class="section">
    <div class="section-title">&#128295; Tool Output</div>
    <div class="tool-grid">{tool_cards}</div>
  </div>
</div>

<div id="tab-findings" class="tab-pane">
  <div class="section">
    <div class="section-title">&#128269; All Findings</div>
    <div class="filter-bar">
      <span style="font-size:12px;font-weight:600;color:#64748b">Filter:</span>
      <button class="filter-btn active" onclick="filterFindings(this,'ALL')">All ({total_findings})</button>
      <button class="filter-btn" style="color:#dc2626" onclick="filterFindings(this,'CRITICAL')">Critical ({findings_c})</button>
      <button class="filter-btn" style="color:#ea580c" onclick="filterFindings(this,'HIGH')">High ({findings_h})</button>
      <button class="filter-btn" style="color:#ca8a04" onclick="filterFindings(this,'MEDIUM')">Medium ({findings_m})</button>
      <button class="filter-btn" style="color:#2563eb" onclick="filterFindings(this,'INFO')">Info ({findings_i})</button>
      <input class="search-box" type="text" placeholder="Search findings or resource names..." oninput="searchFindings(this.value)">
    </div>
    <div class="table-wrap scrollable">
      <table>
        <thead><tr>
          <th style="width:85px">Severity</th>
          <th style="width:160px">Module</th>
          <th style="width:100px">ATT&amp;CK</th>
          <th>Finding</th>
          <th style="width:300px">Affected Resource(s)</th>
          <th style="width:60px">Time</th>
        </tr></thead>
        <tbody id="findings-body">{rows_html}</tbody>
      </table>
    </div>
  </div>
</div>

<div id="tab-resources" class="tab-pane">
  <div class="section">
    <div class="section-title">&#128203; Resource Inventory — All Affected Resources by Category</div>
    <div style="margin-bottom:12px">
      <input class="search-box" style="width:280px" type="text"
             placeholder="Filter resources..." oninput="filterInventory(this.value)">
    </div>
    <div id="inv-container">{inv_html}</div>
  </div>
</div>

<div id="tab-remediation" class="tab-pane">
  <div class="section">
    <div class="section-title">&#128296; Priority Remediation — Critical &amp; High Findings</div>
    <div class="table-wrap scrollable">
      <table>
        <thead><tr>
          <th style="width:85px">Severity</th>
          <th>Finding</th>
          <th style="width:300px">Affected Resource(s)</th>
          <th style="width:100px">ATT&amp;CK</th>
        </tr></thead>
        <tbody>{remed_rows}</tbody>
      </table>
    </div>
  </div>
</div>

<div id="tab-threats" class="tab-pane">
  <div class="section">
    <div class="section-title">&#127919; Threat Model Analysis</div>
    {tm_cards if tm_cards else '<p style="color:#9ca3af;padding:12px">Threat model data not available.</p>'}
  </div>
</div>

<div id="tab-tools" class="tab-pane">
  <div class="section">
    <div class="section-title">&#128295; External Tool Reports</div>
    <div class="tool-grid">{tool_cards}</div>
    <p style="margin-top:16px;font-size:12px;color:#94a3b8">
      Click any available tool link to open its full HTML report.
      Prowler and ScoutSuite contain the most comprehensive per-check detail with
      CIS Azure Benchmark mapping.
    </p>
  </div>
</div>

</div><!-- /container -->

<script>
function showTab(name, btn) {{
  document.querySelectorAll('.tab-pane').forEach(function(p) {{ p.classList.remove('active'); }});
  document.querySelectorAll('.tab-btn').forEach(function(b) {{ b.classList.remove('active'); }});
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
}}

var activeFilter = 'ALL', activeSearch = '';
function filterFindings(btn, sev) {{
  activeFilter = sev;
  document.querySelectorAll('#tab-findings .filter-btn').forEach(function(b) {{ b.classList.remove('active'); }});
  btn.classList.add('active');
  applyFilters();
}}
function searchFindings(q) {{
  activeSearch = q.toLowerCase();
  applyFilters();
}}
function applyFilters() {{
  document.querySelectorAll('.finding-row').forEach(function(row) {{
    var sevOk = activeFilter === 'ALL' || row.dataset.severity === activeFilter;
    var text = (row.textContent + ' ' + (row.dataset.resources || '')).toLowerCase();
    var txtOk = !activeSearch || text.indexOf(activeSearch) > -1;
    row.classList.toggle('hidden', !(sevOk && txtOk));
  }});
}}

function filterInventory(q) {{
  q = q.toLowerCase();
  document.querySelectorAll('.inv-section').forEach(function(sec) {{
    var rows = sec.querySelectorAll('.inv-row');
    var anyVisible = false;
    rows.forEach(function(row) {{
      var match = !q || row.textContent.toLowerCase().indexOf(q) > -1;
      row.style.display = match ? '' : 'none';
      if (match) anyVisible = true;
    }});
    sec.style.display = anyVisible ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    out_path = os.path.join(output_dir, 'reports', 'assessment-report.html')
    with open(out_path, 'w', encoding='utf-8') as fh:
        fh.write(doc)
    print(f"HTML report written: {out_path}")


if __name__ == '__main__':
    main()
