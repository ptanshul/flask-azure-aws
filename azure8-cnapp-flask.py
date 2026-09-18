"""
Azure CNAPP Dashboard  —  Cloud Native Application Protection Platform
Combines: CSPM · CWPP · Identity (CIEM) · Network · Data Security
Port: 5003
"""
import os
import requests as http
from flask import Flask, render_template_string, jsonify
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient

try:
    from azure.mgmt.compute import ComputeManagementClient
    COMPUTE_OK = True
except ImportError:
    COMPUTE_OK = False

try:
    from azure.mgmt.network import NetworkManagementClient
    NETWORK_OK = True
except ImportError:
    NETWORK_OK = False

try:
    from azure.mgmt.keyvault import KeyVaultManagementClient
    KEYVAULT_OK = True
except ImportError:
    KEYVAULT_OK = False

try:
    from azure.mgmt.sql import SqlManagementClient
    SQL_OK = True
except ImportError:
    SQL_OK = False

try:
    from azure.mgmt.containerservice import ContainerServiceClient
    AKS_OK = True
except ImportError:
    AKS_OK = False

try:
    from azure.mgmt.security import SecurityCenter
    SECURITY_OK = True
except ImportError:
    SECURITY_OK = False

load_dotenv()
app = Flask(__name__)
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")

# ── constants ─────────────────────────────────────────────────────────────────

OPEN_SRC       = {"*", "0.0.0.0/0", "Internet", "Any"}
GRAPH_BASE     = "https://graph.microsoft.com/v1.0"
GA_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

PLAN_LABELS = {
    "VirtualMachines": "Virtual Machines", "SqlServers": "SQL Servers (Azure)",
    "SqlServerVirtualMachines": "SQL Servers (VMs)", "AppServices": "App Services",
    "StorageAccounts": "Storage Accounts", "Containers": "Containers / AKS",
    "KeyVaults": "Key Vaults", "Arm": "Azure Resource Manager",
    "Dns": "DNS", "OpenSourceRelationalDatabases": "OSS Relational DBs",
}

CHECK_CVSS = {
    "no_public_blob": 9.1, "https_only": 7.5, "tls_1_2_plus": 5.9,
    "managed_disk": 4.0,   "boot_diagnostics": 2.5,
    "no_open_ssh": 9.8,    "no_open_rdp": 9.8,
    "soft_delete": 4.3,    "purge_protection": 6.5, "network_acl_deny": 7.5,
    "no_public_access": 8.1,
    "rbac_enabled": 8.8,   "network_policy": 6.5,
    "has_tags": 2.0,
    "has_mfa": 9.4,        "not_guest": 9.0, "account_enabled": 5.0,
}

CHECK_DESC = {
    "no_public_blob": "Blob public access is enabled",
    "https_only":     "HTTPS-only traffic not enforced",
    "tls_1_2_plus":   "Minimum TLS version below 1.2",
    "managed_disk":   "Using unmanaged disk",
    "boot_diagnostics":"Boot diagnostics not enabled",
    "no_open_ssh":    "SSH port 22 open to internet (0.0.0.0/0)",
    "no_open_rdp":    "RDP port 3389 open to internet (0.0.0.0/0)",
    "soft_delete":    "Soft delete not enabled on Key Vault",
    "purge_protection":"Purge protection not enabled on Key Vault",
    "network_acl_deny":"Vault network ACL allows public access",
    "no_public_access":"SQL Server has public network access enabled",
    "rbac_enabled":   "AKS cluster RBAC not enabled",
    "network_policy": "AKS cluster has no network policy",
    "has_tags":       "Resource has no governance tags",
    "has_mfa":        "Global Admin has no MFA registered",
    "not_guest":      "Guest user holds Global Administrator role",
    "account_enabled":"Disabled account still holds Global Admin role",
}

SEV_CSS = {
    "Critical": "sc", "High": "sh", "Medium": "sm", "Low": "sl", "Informational": "si"
}

def _cvss_to_sev(score):
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    return "Low"

def _pillar_score(resources):
    if not resources: return 100
    compliant = sum(1 for r in resources if r["status"] == "COMPLIANT")
    return round(compliant / len(resources) * 100, 1)

def _score_css(pct):
    if pct >= 80: return "c-green"
    if pct >= 50: return "c-orange"
    return "c-red"


# ── Graph API helpers ─────────────────────────────────────────────────────────

def _graph_all(token, path, params=None):
    items, data = [], None
    resp = http.get(f"{GRAPH_BASE}{path}", headers={"Authorization": f"Bearer {token}"},
                    params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    items.extend(data.get("value", []))
    while "@odata.nextLink" in (data or {}):
        resp = http.get(data["@odata.nextLink"],
                        headers={"Authorization": f"Bearer {token}"}, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        items.extend(data.get("value", []))
    return items


# ── CSPM resource helper ──────────────────────────────────────────────────────

def _res(name, location, service, pillar, detail, checks):
    passed = sum(1 for v in checks.values() if v)
    total  = len(checks)
    return {
        "name": name, "location": location, "service": service,
        "pillar": pillar, "detail": detail,
        "status": "COMPLIANT" if passed == total else "NON_COMPLIANT",
        "score": f"{passed}/{total}", "checks": checks,
    }


# ── CSPM scanners ─────────────────────────────────────────────────────────────

def scan_storage(cred, sub):
    client = StorageManagementClient(cred, sub)
    return [_res(a.name, a.location, "Storage Accounts", "CSPM", a.sku.name, {
        "no_public_blob": a.allow_blob_public_access is False,
        "https_only":     a.enable_https_traffic_only is True,
        "tls_1_2_plus":   str(a.minimum_tls_version) in ("TLS1_2", "TLS1_3"),
        "has_tags":       bool(a.tags),
    }) for a in client.storage_accounts.list()]


def scan_vms(cred, sub):
    if not COMPUTE_OK: return []
    client = ComputeManagementClient(cred, sub)
    out = []
    for vm in client.virtual_machines.list_all():
        sp, dp = vm.storage_profile, vm.diagnostics_profile
        out.append(_res(vm.name, vm.location, "Virtual Machines", "CWPP",
            f"{vm.hardware_profile.vm_size if vm.hardware_profile else 'N/A'}",
            {"managed_disk":     bool(sp and sp.os_disk and sp.os_disk.managed_disk),
             "boot_diagnostics": bool(dp and dp.boot_diagnostics and dp.boot_diagnostics.enabled),
             "has_tags":         bool(vm.tags)}))
    return out


def scan_nsgs(cred, sub):
    if not NETWORK_OK: return []
    client = NetworkManagementClient(cred, sub)
    out = []
    for nsg in client.network_security_groups.list_all():
        ssh_open = rdp_open = False
        for rule in (nsg.security_rules or []):
            if rule.direction != "Inbound" or rule.access != "Allow": continue
            if (rule.source_address_prefix or "") not in OPEN_SRC: continue
            ports = {rule.destination_port_range or ""} | set(rule.destination_port_ranges or [])
            if "22"   in ports or "*" in ports: ssh_open = True
            if "3389" in ports or "*" in ports: rdp_open = True
        out.append(_res(nsg.name, nsg.location, "Network Security Groups", "Network",
            f"{len(nsg.security_rules or [])} rules",
            {"no_open_ssh": not ssh_open, "no_open_rdp": not rdp_open,
             "has_tags": bool(nsg.tags)}))
    return out


def scan_keyvaults(cred, sub):
    if not KEYVAULT_OK: return []
    client = KeyVaultManagementClient(cred, sub)
    out = []
    for vault in client.vaults.list_by_subscription():
        props = vault.properties
        acl_deny = bool(props and props.network_acls and
                        props.network_acls.default_action == "Deny")
        out.append(_res(vault.name, vault.location, "Key Vaults", "Data",
            props.sku.name if props and props.sku else "N/A",
            {"soft_delete":      bool(props and props.enable_soft_delete),
             "purge_protection": bool(props and props.enable_purge_protection),
             "network_acl_deny": acl_deny, "has_tags": bool(vault.tags)}))
    return out


def scan_sql(cred, sub):
    if not SQL_OK: return []
    client = SqlManagementClient(cred, sub)
    out = []
    for srv in client.servers.list():
        tls = getattr(srv, "minimal_tls_version", "") or ""
        out.append(_res(srv.name, srv.location, "SQL Servers", "Data",
            f"v{srv.version}" if srv.version else "N/A",
            {"no_public_access": getattr(srv, "public_network_access", "Enabled") == "Disabled",
             "tls_1_2_plus": tls in ("1.2", "1.3"), "has_tags": bool(srv.tags)}))
    return out


def scan_aks(cred, sub):
    if not AKS_OK: return []
    client = ContainerServiceClient(cred, sub)
    out = []
    for cluster in client.managed_clusters.list():
        np = cluster.network_profile
        out.append(_res(cluster.name, cluster.location, "AKS Clusters", "CWPP",
            f"k8s {cluster.kubernetes_version or 'N/A'}",
            {"rbac_enabled":   bool(cluster.enable_rbac),
             "network_policy": bool(np and np.network_policy),
             "has_tags":       bool(cluster.tags)}))
    return out


def scan_entra_admins(cred):
    try:
        token = cred.get_token("https://graph.microsoft.com/.default").token
    except Exception:
        return []
    roles = _graph_all(token, "/directoryRoles")
    ga = next((r for r in roles if r.get("roleTemplateId") == GA_TEMPLATE_ID), None)
    if not ga: return []
    SELECT = "id,displayName,userPrincipalName,accountEnabled,userType,country"
    members = _graph_all(token, f"/directoryRoles/{ga['id']}/members",
                         params={"$select": SELECT})
    out = []
    for m in members:
        uid, has_mfa = m.get("id", ""), True
        try:
            methods = _graph_all(token, f"/users/{uid}/authentication/methods")
            non_pwd = [x for x in methods
                       if "passwordAuthentication" not in x.get("@odata.type", "")]
            has_mfa = len(non_pwd) > 0
        except Exception:
            pass
        out.append(_res(
            m.get("displayName") or "Unknown",
            m.get("country") or "Global",
            "Entra ID", "Identity",
            m.get("userPrincipalName") or uid,
            {"has_mfa":        has_mfa,
             "not_guest":      (m.get("userType") or "Member") != "Guest",
             "account_enabled": m.get("accountEnabled", True)}))
    return out


def scan_defender_plans(sub):
    if not SECURITY_OK: return []
    cred = DefaultAzureCredential()
    try:
        client = SecurityCenter(credential=cred, subscription_id=sub)
    except TypeError:
        client = SecurityCenter(credential=cred, subscription_id=sub, asc_location="eastus")
    try:
        result = client.pricings.list(scope_id=f"/subscriptions/{sub}")
    except TypeError:
        result = client.pricings.list()
    items = result.value if hasattr(result, "value") else result
    return [{"id": p.name, "name": PLAN_LABELS.get(p.name, p.name),
             "tier": p.pricing_tier, "enabled": p.pricing_tier == "Standard"}
            for p in items]


def scan_alerts(sub):
    if not SECURITY_OK: return []
    cred = DefaultAzureCredential()
    try:
        client = SecurityCenter(credential=cred, subscription_id=sub)
    except TypeError:
        client = SecurityCenter(credential=cred, subscription_id=sub, asc_location="eastus")
    out = []
    for a in client.alerts.list():
        if getattr(a, "status", "Active") in ("Dismissed", "Resolved"): continue
        sev = getattr(a, "severity", "Medium") or "Medium"
        out.append({
            "name":     (getattr(a, "alert_display_name", "") or getattr(a, "alert_type", "Alert")),
            "severity": sev, "sev_css": SEV_CSS.get(sev, "sm"),
            "resource": getattr(a, "compromised_entity", "N/A") or "N/A",
        })
    return out


# ── findings aggregator ───────────────────────────────────────────────────────

def build_findings(resources):
    findings = []
    for r in resources:
        for key, passed in r["checks"].items():
            if passed: continue
            cvss = CHECK_CVSS.get(key, 2.0)
            sev  = _cvss_to_sev(cvss)
            findings.append({
                "severity":  sev,
                "sev_order": {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(sev, 4),
                "sev_css":   SEV_CSS.get(sev, "sm"),
                "pillar":    r["pillar"],
                "service":   r["service"],
                "resource":  r["name"],
                "issue":     CHECK_DESC.get(key, key),
                "cvss":      cvss,
            })
    return sorted(findings, key=lambda x: x["sev_order"])


# ── HTML template ─────────────────────────────────────────────────────────────

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Azure CNAPP Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: Segoe UI, Arial, sans-serif; background: #f0f2f5; color: #1a1a1a; }

    header {
      background: linear-gradient(135deg, #1e1b4b 0%, #312e81 60%, #4338ca 100%);
      color: #fff; padding: 18px 32px;
      display: flex; justify-content: space-between; align-items: center;
    }
    header h1 { font-size: 1.4rem; font-weight: 700; letter-spacing: -.3px; }
    header .sub { font-size: 0.78rem; opacity: 0.7; margin-top: 3px; }

    .header-right { display: flex; align-items: center; gap: 14px; }
    .risk-box {
      background: rgba(0,0,0,.3); border: 1px solid rgba(255,255,255,.2);
      border-radius: 10px; padding: 10px 22px; text-align: center; min-width: 130px;
    }
    .risk-box .rb-title { font-size: 0.6rem; text-transform: uppercase; letter-spacing: 1.2px; opacity: .75; margin-bottom: 3px; }
    .risk-box .rb-score { font-size: 2.3rem; font-weight: 800; line-height: 1; }
    .risk-box .rb-label { font-size: 0.67rem; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; margin-top: 3px; }
    .rc { color: #ff5252; } .rh { color: #ff8a65; } .rm { color: #ffb74d; }
    .rl { color: #a8e6a3; } .rn { color: #a8e6a3; }

    .refresh-btn { color: #fff; text-decoration: none; font-size: 0.8rem;
      border: 1px solid rgba(255,255,255,.35); padding: 5px 14px; border-radius: 4px; }
    .refresh-btn:hover { background: rgba(255,255,255,.1); }

    /* Pillar cards */
    .pillars { display: flex; gap: 14px; padding: 20px 32px 0; flex-wrap: wrap; }
    .pillar-card {
      background: #fff; border-radius: 8px; padding: 16px 20px;
      min-width: 175px; flex: 1;
      box-shadow: 0 1px 3px rgba(0,0,0,.1);
      border-top: 4px solid var(--pc);
    }
    .pillar-card .pc-icon  { font-size: 1.3rem; }
    .pillar-card .pc-name  { font-size: 0.72rem; color: #666; text-transform: uppercase; letter-spacing: .5px; margin-top: 6px; }
    .pillar-card .pc-score { font-size: 2rem; font-weight: 800; margin-top: 2px; }
    .pillar-card .pc-meta  { font-size: 0.75rem; color: #888; margin-top: 4px; }
    .c-green  { color: #107c10; } .c-orange { color: #e07000; } .c-red { color: #d13438; }
    .c-blue   { color: #0078d4; } .c-purple { color: #6366f1; }

    /* Tabs */
    .tabs { display: flex; margin: 20px 32px 0; border-bottom: 2px solid #ddd; overflow-x: auto; }
    .tab-btn {
      background: none; border: none; cursor: pointer;
      padding: 10px 18px; font-size: 0.84rem; color: #555;
      border-bottom: 3px solid transparent; margin-bottom: -2px;
      white-space: nowrap; display: flex; align-items: center; gap: 6px;
    }
    .tab-btn:hover { color: #4338ca; background: #f5f5ff; }
    .tab-btn.active { color: #4338ca; border-bottom-color: #4338ca; font-weight: 600; }
    .tbadge { background: #eee; color: #555; border-radius: 10px; padding: 1px 7px; font-size: 0.72rem; font-weight: 700; }
    .tab-btn.active .tbadge { background: #ede9fe; color: #4338ca; }

    /* Panels */
    .panel { display: none; padding: 20px 32px; }
    .panel.active { display: block; }
    .panel-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
    .panel-head h2 { font-size: 1rem; font-weight: 600; color: #333; }
    .counters { display: flex; gap: 8px; }
    .ctr { font-size: 0.78rem; font-weight: 600; padding: 3px 11px; border-radius: 12px; }
    .ctr.g  { background: #dff6dd; color: #107c10; }
    .ctr.r  { background: #fde7e9; color: #d13438; }
    .ctr.o  { background: #fff4ce; color: #8a5700; }
    .ctr.p  { background: #ede9fe; color: #4338ca; }
    .ctr.gr { background: #eee; color: #777; }

    /* Tables */
    table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 6px;
      overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); font-size: 0.845rem; }
    th { background: #f7f7f7; text-align: left; padding: 10px 13px; font-weight: 600;
      border-bottom: 2px solid #e1e1e1; white-space: nowrap; color: #444; }
    td { padding: 9px 13px; border-bottom: 1px solid #f0f0f0; vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #faf9ff; }

    /* Severity badges */
    .sev { display: inline-block; padding: 2px 9px; border-radius: 10px; font-size: 0.73rem; font-weight: 700; }
    .sc { background: #fde7e9; color: #9b1c1c; border: 1px solid #fca5a5; }
    .sh { background: #fde7e9; color: #d13438; }
    .sm { background: #fff4ce; color: #8a5700; }
    .sl { background: #dff6dd; color: #107c10; }
    .si { background: #ddeeff; color: #0078d4; }

    /* Status badges */
    .sbadge { display: inline-block; padding: 2px 9px; border-radius: 10px; font-size: 0.73rem; font-weight: 700; }
    .sbadge.ok  { background: #dff6dd; color: #107c10; }
    .sbadge.nok { background: #fde7e9; color: #d13438; }

    /* Pillar tag */
    .ptag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; }
    .pt-cspm     { background: #ddeeff; color: #0055aa; }
    .pt-cwpp     { background: #ede9fe; color: #4338ca; }
    .pt-identity { background: #d1fae5; color: #065f46; }
    .pt-network  { background: #dff6dd; color: #107c10; }
    .pt-data     { background: #fff4ce; color: #8a5700; }

    /* Progress bar */
    .pg-wrap { background: #eee; border-radius: 4px; height: 6px; width: 100px; display: inline-block; vertical-align: middle; overflow: hidden; margin-right: 6px; }
    .pg-bar  { height: 100%; border-radius: 4px; }
    .pg-g { background: #107c10; } .pg-o { background: #e07000; } .pg-r { background: #d13438; }

    .chk { text-align: center; font-size: 1rem; }
    .chk.p { color: #107c10; } .chk.f { color: #d13438; }
    .score { font-weight: 700; font-size: 0.82rem; }
    .score.full { color: #107c10; } .score.part { color: #e07000; } .score.zero { color: #d13438; }

    .empty { text-align: center; padding: 36px; color: #aaa; font-size: 0.9rem; }
    .warn  { background: #fff4ce; border: 1px solid #f0c000; border-radius: 6px;
             padding: 10px 14px; font-size: 0.84rem; color: #6b4f00; margin-bottom: 14px; }

    footer { padding: 14px 32px; font-size: 0.78rem; color: #888; border-top: 1px solid #e1e1e1; margin-top: 8px; }
    footer a { color: #6366f1; text-decoration: none; margin-right: 14px; }
    footer a:hover { text-decoration: underline; }
  </style>
</head>
<body>

<header>
  <div>
    <h1>&#9729; Azure CNAPP Dashboard</h1>
    <div class="sub">Cloud Native Application Protection &nbsp;|&nbsp; Subscription: {{ subscription_id }}</div>
  </div>
  <div class="header-right">
    <div class="risk-box">
      <div class="rb-title">CNAPP Risk Score</div>
      <div class="rb-score {{ risk_css }}">{{ risk_score }}</div>
      <div class="rb-label {{ risk_css }}">{{ risk_label }}</div>
    </div>
    <a class="refresh-btn" href="/">&#8635; Refresh</a>
  </div>
</header>

<!-- Pillar Cards -->
<div class="pillars">
  {% for p in pillars %}
  {% set sc = _score_css(p.score) %}
  {% set pg = 'pg-g' if p.score >= 80 else ('pg-o' if p.score >= 50 else 'pg-r') %}
  <div class="pillar-card" style="--pc:{{ p.color }}">
    <div class="pc-icon">{{ p.icon | safe }}</div>
    <div class="pc-name">{{ p.name }}</div>
    <div class="pc-score {{ sc }}">{{ p.score }}%</div>
    <div class="pc-meta">
      <div class="pg-wrap"><div class="pg-bar {{ pg }}" style="width:{{ p.score }}%"></div></div>
      {{ p.issues }} issue{{ 's' if p.issues != 1 else '' }}
    </div>
  </div>
  {% endfor %}
</div>

<!-- Tabs -->
<div class="tabs">
  <button class="tab-btn" data-tab="overview" onclick="showTab('overview')">
    &#9729; Overview <span class="tbadge">{{ findings | length }}</span>
  </button>
  <button class="tab-btn" data-tab="cspm" onclick="showTab('cspm')">
    &#9745; CSPM <span class="tbadge">{{ cspm_resources | length }}</span>
  </button>
  <button class="tab-btn" data-tab="cwpp" onclick="showTab('cwpp')">
    &#128737; Workload <span class="tbadge">{{ vms | length + aks | length }}</span>
  </button>
  <button class="tab-btn" data-tab="identity" onclick="showTab('identity')">
    &#128100; Identity <span class="tbadge">{{ identity | length }}</span>
  </button>
  <button class="tab-btn" data-tab="network" onclick="showTab('network')">
    &#128274; Network <span class="tbadge">{{ nsgs | length }}</span>
  </button>
  <button class="tab-btn" data-tab="findings" onclick="showTab('findings')">
    &#128204; All Findings <span class="tbadge">{{ findings | length }}</span>
  </button>
</div>

<!-- ── OVERVIEW ───────────────────────────────────────────────────────────── -->
<div class="panel" id="tab-overview">
  <div class="panel-head">
    <h2>&#9729; CNAPP Risk Overview — Top Critical Findings</h2>
    <div class="counters">
      {% set crit = findings | selectattr('sev_css','equalto','sc') | list | length %}
      {% set high = findings | selectattr('sev_css','equalto','sh') | list | length %}
      <span class="ctr r">{{ crit }} Critical</span>
      <span class="ctr o">{{ high }} High</span>
      <span class="ctr p">{{ findings | length }} Total</span>
    </div>
  </div>
  {% if findings %}
  <table>
    <thead>
      <tr><th>#</th><th>Severity</th><th>Pillar</th><th>Service</th><th>Resource</th><th>Issue</th><th>CVSS</th></tr>
    </thead>
    <tbody>
      {% for f in findings[:25] %}
      <tr>
        <td style="color:#aaa;font-size:0.8rem;">{{ loop.index }}</td>
        <td><span class="sev {{ f.sev_css }}">{{ f.severity }}</span></td>
        <td><span class="ptag pt-{{ f.pillar | lower }}">{{ f.pillar }}</span></td>
        <td style="font-size:0.82rem;color:#555;">{{ f.service }}</td>
        <td><strong>{{ f.resource }}</strong></td>
        <td style="font-size:0.82rem;">{{ f.issue }}</td>
        <td style="font-weight:700;color:{{ '#9b1c1c' if f.cvss>=9 else ('#d13438' if f.cvss>=7 else ('#e07000' if f.cvss>=4 else '#107c10')) }}">{{ f.cvss }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">&#10003; No findings detected across all pillars.</div>
  {% endif %}
</div>

<!-- ── CSPM ───────────────────────────────────────────────────────────────── -->
<div class="panel" id="tab-cspm">
  <div class="panel-head">
    <h2>&#9745; Cloud Security Posture — All Resources</h2>
    <div class="counters">
      {% set comp = cspm_resources | selectattr('status','equalto','COMPLIANT') | list | length %}
      <span class="ctr g">{{ comp }} Compliant</span>
      <span class="ctr r">{{ cspm_resources | length - comp }} Non-Compliant</span>
    </div>
  </div>
  {% if cspm_resources %}
  <table>
    <thead>
      <tr><th>#</th><th>Resource</th><th>Service</th><th>Location</th><th>Detail</th><th>Status</th><th>Score</th></tr>
    </thead>
    <tbody>
      {% for r in cspm_resources %}
      {% set parts = r.score.split('/') %}
      {% set p = parts[0]|int %} {% set t = parts[1]|int %}
      <tr>
        <td style="color:#aaa;font-size:0.8rem;">{{ loop.index }}</td>
        <td><strong>{{ r.name }}</strong></td>
        <td style="font-size:0.8rem;"><span class="ptag pt-{{ r.pillar|lower }}">{{ r.service }}</span></td>
        <td style="font-size:0.8rem;color:#666;">{{ r.location }}</td>
        <td style="font-size:0.8rem;color:#888;">{{ r.detail }}</td>
        <td><span class="sbadge {{ 'ok' if r.status=='COMPLIANT' else 'nok' }}">
          {{ 'COMPLIANT' if r.status=='COMPLIANT' else 'NON-COMPLIANT' }}
        </span></td>
        <td><span class="score {% if p==t %}full{% elif p==0 %}zero{% else %}part{% endif %}">{{ r.score }}</span></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">No CSPM resources found.</div>
  {% endif %}
</div>

<!-- ── CWPP ───────────────────────────────────────────────────────────────── -->
<div class="panel" id="tab-cwpp">
  {% if not security_ok %}
  <div class="warn">&#9888; azure-mgmt-security not installed — Defender plan data unavailable. Run: pip install azure-mgmt-security</div>
  {% endif %}
  <div class="panel-head">
    <h2>&#128737; Workload Protection — Defender Plans</h2>
    <div class="counters">
      {% set en = defender_plans | selectattr('enabled') | list | length %}
      <span class="ctr g">{{ en }} Protected</span>
      <span class="ctr r">{{ defender_plans | length - en }} Unprotected</span>
    </div>
  </div>
  {% if defender_plans %}
  <table>
    <thead><tr><th>#</th><th>Workload</th><th>Plan ID</th><th>Tier</th><th>Status</th></tr></thead>
    <tbody>
      {% for p in defender_plans %}
      <tr>
        <td style="color:#aaa;font-size:0.8rem;">{{ loop.index }}</td>
        <td><strong>{{ p.name }}</strong></td>
        <td style="color:#999;font-size:0.8rem;">{{ p.id }}</td>
        <td>{{ p.tier }}</td>
        <td><span class="sbadge {{ 'ok' if p.enabled else 'nok' }}">
          {{ '&#10003; PROTECTED' if p.enabled else '&#10007; UNPROTECTED' }}
        </span></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">No Defender plan data available.</div>
  {% endif %}

  <div class="panel-head" style="margin-top:24px;">
    <h2>&#128421; Virtual Machines &amp; AKS Clusters</h2>
    <div class="counters">
      {% set wcomp = (vms + aks) | selectattr('status','equalto','COMPLIANT') | list | length %}
      <span class="ctr g">{{ wcomp }} Compliant</span>
      <span class="ctr r">{{ (vms+aks)|length - wcomp }} Non-Compliant</span>
    </div>
  </div>
  {% if vms or aks %}
  <table>
    <thead><tr><th>#</th><th>Resource</th><th>Type</th><th>Detail</th><th>Status</th><th>Score</th></tr></thead>
    <tbody>
      {% for r in vms + aks %}
      {% set parts = r.score.split('/') %}{% set p = parts[0]|int %}{% set t = parts[1]|int %}
      <tr>
        <td style="color:#aaa;font-size:0.8rem;">{{ loop.index }}</td>
        <td><strong>{{ r.name }}</strong></td>
        <td style="font-size:0.8rem;color:#555;">{{ r.service }}</td>
        <td style="font-size:0.8rem;color:#888;">{{ r.detail }}</td>
        <td><span class="sbadge {{ 'ok' if r.status=='COMPLIANT' else 'nok' }}">
          {{ 'COMPLIANT' if r.status=='COMPLIANT' else 'NON-COMPLIANT' }}
        </span></td>
        <td><span class="score {% if p==t %}full{% elif p==0 %}zero{% else %}part{% endif %}">{{ r.score }}</span></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">No VMs or AKS clusters found.</div>
  {% endif %}
</div>

<!-- ── IDENTITY ───────────────────────────────────────────────────────────── -->
<div class="panel" id="tab-identity">
  <div class="panel-head">
    <h2>&#128100; Identity Security — Entra ID Global Administrators</h2>
    <div class="counters">
      {% set icomp = identity | selectattr('status','equalto','COMPLIANT') | list | length %}
      <span class="ctr g">{{ icomp }} Compliant</span>
      <span class="ctr r">{{ identity|length - icomp }} Non-Compliant</span>
    </div>
  </div>
  {% if identity %}
  <table>
    <thead>
      <tr><th>#</th><th>Display Name</th><th>UPN</th><th>Country</th><th>Status</th><th>Score</th><th>MFA</th><th>Not Guest</th><th>Active</th></tr>
    </thead>
    <tbody>
      {% for r in identity %}
      <tr>
        <td style="color:#aaa;font-size:0.8rem;">{{ loop.index }}</td>
        <td><strong>{{ r.name }}</strong></td>
        <td style="font-size:0.8rem;color:#555;">{{ r.detail }}</td>
        <td style="font-size:0.8rem;color:#888;">{{ r.location }}</td>
        <td><span class="sbadge {{ 'ok' if r.status=='COMPLIANT' else 'nok' }}">
          {{ 'COMPLIANT' if r.status=='COMPLIANT' else 'NON-COMPLIANT' }}
        </span></td>
        {% set parts = r.score.split('/') %}{% set p=parts[0]|int %}{% set t=parts[1]|int %}
        <td><span class="score {% if p==t %}full{% elif p==0 %}zero{% else %}part{% endif %}">{{ r.score }}</span></td>
        <td class="chk {{ 'p' if r.checks.has_mfa else 'f' }}">{{ '&#10003;' if r.checks.has_mfa else '&#10007;' }}</td>
        <td class="chk {{ 'p' if r.checks.not_guest else 'f' }}">{{ '&#10003;' if r.checks.not_guest else '&#10007;' }}</td>
        <td class="chk {{ 'p' if r.checks.account_enabled else 'f' }}">{{ '&#10003;' if r.checks.account_enabled else '&#10007;' }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">No Global Administrators found or Graph API permission missing.</div>
  {% endif %}
</div>

<!-- ── NETWORK ────────────────────────────────────────────────────────────── -->
<div class="panel" id="tab-network">
  <div class="panel-head">
    <h2>&#128274; Network Security — Security Groups</h2>
    <div class="counters">
      {% set ncomp = nsgs | selectattr('status','equalto','COMPLIANT') | list | length %}
      <span class="ctr g">{{ ncomp }} Compliant</span>
      <span class="ctr r">{{ nsgs|length - ncomp }} Non-Compliant</span>
    </div>
  </div>
  {% if nsgs %}
  <table>
    <thead>
      <tr><th>#</th><th>NSG Name</th><th>Location</th><th>Rules</th><th>Status</th><th>Score</th><th>No Open SSH</th><th>No Open RDP</th><th>Tags</th></tr>
    </thead>
    <tbody>
      {% for r in nsgs %}
      {% set parts = r.score.split('/') %}{% set p=parts[0]|int %}{% set t=parts[1]|int %}
      <tr>
        <td style="color:#aaa;font-size:0.8rem;">{{ loop.index }}</td>
        <td><strong>{{ r.name }}</strong></td>
        <td style="font-size:0.8rem;color:#666;">{{ r.location }}</td>
        <td style="font-size:0.8rem;color:#888;">{{ r.detail }}</td>
        <td><span class="sbadge {{ 'ok' if r.status=='COMPLIANT' else 'nok' }}">
          {{ 'COMPLIANT' if r.status=='COMPLIANT' else 'NON-COMPLIANT' }}
        </span></td>
        <td><span class="score {% if p==t %}full{% elif p==0 %}zero{% else %}part{% endif %}">{{ r.score }}</span></td>
        <td class="chk {{ 'p' if r.checks.no_open_ssh else 'f' }}">{{ '&#10003;' if r.checks.no_open_ssh else '&#10007;' }}</td>
        <td class="chk {{ 'p' if r.checks.no_open_rdp else 'f' }}">{{ '&#10003;' if r.checks.no_open_rdp else '&#10007;' }}</td>
        <td class="chk {{ 'p' if r.checks.has_tags else 'f' }}">{{ '&#10003;' if r.checks.has_tags else '&#10007;' }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">No Network Security Groups found or azure-mgmt-network not installed.</div>
  {% endif %}
</div>

<!-- ── ALL FINDINGS ───────────────────────────────────────────────────────── -->
<div class="panel" id="tab-findings">
  <div class="panel-head">
    <h2>&#128204; All Findings — Prioritized by Severity</h2>
    <div class="counters">
      {% set fc = findings | selectattr('sev_css','equalto','sc') | list | length %}
      {% set fh = findings | selectattr('sev_css','equalto','sh') | list | length %}
      {% set fm = findings | selectattr('sev_css','equalto','sm') | list | length %}
      <span class="ctr r">{{ fc }} Critical</span>
      <span class="ctr o">{{ fh }} High</span>
      <span class="ctr gr">{{ fm }} Medium</span>
    </div>
  </div>
  {% if findings %}
  <table>
    <thead>
      <tr><th>#</th><th>Severity</th><th>CVSS</th><th>Pillar</th><th>Service</th><th>Resource</th><th>Issue</th></tr>
    </thead>
    <tbody>
      {% for f in findings %}
      <tr>
        <td style="color:#aaa;font-size:0.8rem;">{{ loop.index }}</td>
        <td><span class="sev {{ f.sev_css }}">{{ f.severity }}</span></td>
        <td style="font-weight:700;color:{{ '#9b1c1c' if f.cvss>=9 else ('#d13438' if f.cvss>=7 else ('#e07000' if f.cvss>=4 else '#107c10')) }}">{{ f.cvss }}</td>
        <td><span class="ptag pt-{{ f.pillar|lower }}">{{ f.pillar }}</span></td>
        <td style="font-size:0.82rem;color:#555;">{{ f.service }}</td>
        <td><strong>{{ f.resource }}</strong></td>
        <td style="font-size:0.82rem;">{{ f.issue }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">&#10003; No findings across any pillar — environment is clean!</div>
  {% endif %}
</div>

<footer>
  <a href="/api/cnapp">JSON: Full CNAPP Report</a>
  <a href="/api/findings">JSON: All Findings</a>
  <a href="/api/cspm">JSON: CSPM Resources</a>
  <a href="/api/identity">JSON: Identity</a>
</footer>

<script>
  function showTab(id) {
    document.querySelectorAll('.panel').forEach(function(p) { p.classList.remove('active'); });
    document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    document.getElementById('tab-' + id).classList.add('active');
    document.querySelector('[data-tab="' + id + '"]').classList.add('active');
  }
  window.addEventListener('DOMContentLoaded', function() { showTab('overview'); });
</script>
</body>
</html>"""


# ── routes ────────────────────────────────────────────────────────────────────

def _collect(sub):
    cred = DefaultAzureCredential()

    storage   = scan_storage(cred, sub)
    vms       = scan_vms(cred, sub)
    nsgs      = scan_nsgs(cred, sub)
    keyvaults = scan_keyvaults(cred, sub)
    sql       = scan_sql(cred, sub)
    aks       = scan_aks(cred, sub)
    identity  = scan_entra_admins(cred)

    cspm_resources = storage + keyvaults + sql
    all_resources  = storage + vms + nsgs + keyvaults + sql + aks + identity

    findings = build_findings(all_resources)

    # Defender plans (optional)
    defender_plans = scan_defender_plans(sub)
    alerts         = scan_alerts(sub)

    # Pillar scores
    nsg_score  = _pillar_score(nsgs)
    data_score = _pillar_score(storage + keyvaults + sql)
    cwpp_score = _pillar_score(vms + aks)
    if defender_plans:
        enabled_pct = round(sum(1 for p in defender_plans if p["enabled"]) / len(defender_plans) * 100, 1)
        cwpp_score  = round((cwpp_score + enabled_pct) / 2, 1)
    cspm_score = _pillar_score(cspm_resources)
    id_score   = _pillar_score(identity)

    pillars = [
        {"name": "Cloud Posture",   "icon": "&#9745;",   "color": "#0078d4", "score": cspm_score,
         "issues": sum(1 for r in cspm_resources if r["status"] == "NON_COMPLIANT")},
        {"name": "Workload Prot.",  "icon": "&#128737;", "color": "#6366f1", "score": cwpp_score,
         "issues": sum(1 for r in vms + aks if r["status"] == "NON_COMPLIANT")},
        {"name": "Identity",        "icon": "&#128100;", "color": "#059669", "score": id_score,
         "issues": sum(1 for r in identity if r["status"] == "NON_COMPLIANT")},
        {"name": "Network",         "icon": "&#128274;", "color": "#107c10", "score": nsg_score,
         "issues": sum(1 for r in nsgs if r["status"] == "NON_COMPLIANT")},
        {"name": "Data Security",   "icon": "&#128196;", "color": "#e07000", "score": data_score,
         "issues": sum(1 for r in storage + keyvaults + sql if r["status"] == "NON_COMPLIANT")},
    ]

    # CNAPP risk score = max CVSS across all findings
    max_cvss   = max((f["cvss"] for f in findings), default=0.0)
    risk_score = round(max_cvss, 1)
    risk_label = _cvss_to_sev(risk_score) if risk_score > 0 else "None"
    risk_css   = {"Critical": "rc", "High": "rh", "Medium": "rm", "Low": "rl"}.get(risk_label, "rn")

    return dict(
        subscription_id=sub, pillars=pillars,
        cspm_resources=cspm_resources, vms=vms, nsgs=nsgs, aks=aks,
        identity=identity, defender_plans=defender_plans, alerts=alerts,
        findings=findings, risk_score=risk_score, risk_label=risk_label,
        risk_css=risk_css, security_ok=SECURITY_OK,
    )


@app.route("/")
def dashboard():
    if not SUBSCRIPTION_ID:
        return "<pre style='padding:32px'>AZURE_SUBSCRIPTION_ID not set in .env</pre>", 500
    try:
        data = _collect(SUBSCRIPTION_ID)
        return render_template_string(TEMPLATE, _score_css=_score_css, **data)
    except Exception as exc:
        return f"<pre style='padding:32px'>Error: {exc}</pre>", 500


@app.route("/api/cnapp")
def api_cnapp():
    try:
        data = _collect(SUBSCRIPTION_ID)
        data.pop("_score_css", None)
        return jsonify(data)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/findings")
def api_findings():
    try:
        return jsonify(build_findings(
            scan_storage(DefaultAzureCredential(), SUBSCRIPTION_ID) +
            scan_nsgs(DefaultAzureCredential(), SUBSCRIPTION_ID) +
            scan_entra_admins(DefaultAzureCredential())
        ))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/cspm")
def api_cspm():
    try:
        cred = DefaultAzureCredential()
        return jsonify(scan_storage(cred, SUBSCRIPTION_ID) +
                       scan_keyvaults(cred, SUBSCRIPTION_ID) +
                       scan_sql(cred, SUBSCRIPTION_ID))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/identity")
def api_identity():
    try:
        return jsonify(scan_entra_admins(DefaultAzureCredential()))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5003, debug=True)
