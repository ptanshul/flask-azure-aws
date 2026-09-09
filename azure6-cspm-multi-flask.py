import os
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

load_dotenv()
app = Flask(__name__)
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")

OPEN_SRC = {"*", "0.0.0.0/0", "Internet", "Any"}
INSTALL_HINT = {
    "vms":       "pip install azure-mgmt-compute",
    "nsgs":      "pip install azure-mgmt-network",
    "keyvaults": "pip install azure-mgmt-keyvault",
    "sql":       "pip install azure-mgmt-sql",
    "aks":       "pip install azure-mgmt-containerservice",
}

# CVSS v3.1 base scores assigned per check (worst-case exposure if the check fails)
CHECK_CVSS = {
    "no_public_blob":   9.1,  # Critical — unauthenticated public data read
    "https_only":       7.5,  # High    — cleartext data in transit
    "tls_1_2_plus":     5.9,  # Medium  — weak TLS negotiation
    "managed_disk":     4.0,  # Medium  — unmanaged disk integrity risk
    "boot_diagnostics": 2.5,  # Low     — limits post-incident forensics
    "no_open_ssh":      9.8,  # Critical — internet-exposed SSH attack surface
    "no_open_rdp":      9.8,  # Critical — internet-exposed RDP attack surface
    "soft_delete":      4.3,  # Medium  — accidental / malicious data deletion
    "purge_protection": 6.5,  # Medium  — permanent secret/key destruction
    "network_acl_deny": 7.5,  # High    — vault reachable from public internet
    "no_public_access": 8.1,  # High    — publicly reachable SQL server
    "rbac_enabled":     8.8,  # High    — privilege escalation in cluster
    "network_policy":   6.5,  # Medium  — unrestricted pod-to-pod traffic
    "has_tags":         2.0,  # Low     — governance / cost attribution gap
}


# ── helpers ───────────────────────────────────────────────────────────────────

def _result(name, location, detail, checks):
    passed = sum(1 for v in checks.values() if v)
    total = len(checks)
    return {
        "name": name, "location": location, "detail": detail,
        "status": "COMPLIANT" if passed == total else "NON_COMPLIANT",
        "score": f"{passed}/{total}", "checks": checks,
    }


# ── scanners ──────────────────────────────────────────────────────────────────

def scan_storage(cred, sub):
    client = StorageManagementClient(cred, sub)
    out = []
    for a in client.storage_accounts.list():
        out.append(_result(a.name, a.location, a.sku.name, {
            "no_public_blob": a.allow_blob_public_access is False,
            "https_only":     a.enable_https_traffic_only is True,
            "tls_1_2_plus":   str(a.minimum_tls_version) in ("TLS1_2", "TLS1_3"),
            "has_tags":       bool(a.tags),
        }))
    return out


def scan_vms(cred, sub):
    if not COMPUTE_OK:
        return None
    client = ComputeManagementClient(cred, sub)
    out = []
    for vm in client.virtual_machines.list_all():
        sp = vm.storage_profile
        dp = vm.diagnostics_profile
        os_type = sp.os_disk.os_type if sp and sp.os_disk else "N/A"
        size = vm.hardware_profile.vm_size if vm.hardware_profile else "N/A"
        out.append(_result(vm.name, vm.location, f"{size} / {os_type}", {
            "managed_disk":     bool(sp and sp.os_disk and sp.os_disk.managed_disk),
            "boot_diagnostics": bool(dp and dp.boot_diagnostics and dp.boot_diagnostics.enabled),
            "has_tags":         bool(vm.tags),
        }))
    return out


def scan_nsgs(cred, sub):
    if not NETWORK_OK:
        return None
    client = NetworkManagementClient(cred, sub)
    out = []
    for nsg in client.network_security_groups.list_all():
        ssh_open = rdp_open = False
        for rule in (nsg.security_rules or []):
            if rule.direction != "Inbound" or rule.access != "Allow":
                continue
            if (rule.source_address_prefix or "") not in OPEN_SRC:
                continue
            ports = {rule.destination_port_range or ""} | set(rule.destination_port_ranges or [])
            if "22" in ports or "*" in ports:
                ssh_open = True
            if "3389" in ports or "*" in ports:
                rdp_open = True
        out.append(_result(nsg.name, nsg.location, f"{len(nsg.security_rules or [])} rules", {
            "no_open_ssh": not ssh_open,
            "no_open_rdp": not rdp_open,
            "has_tags":    bool(nsg.tags),
        }))
    return out


def scan_keyvaults(cred, sub):
    if not KEYVAULT_OK:
        return None
    client = KeyVaultManagementClient(cred, sub)
    out = []
    for vault in client.vaults.list_by_subscription():
        props = vault.properties
        acl_deny = bool(
            props and props.network_acls and
            props.network_acls.default_action == "Deny"
        )
        out.append(_result(
            vault.name, vault.location,
            props.sku.name if props and props.sku else "N/A", {
                "soft_delete":      bool(props and props.enable_soft_delete),
                "purge_protection": bool(props and props.enable_purge_protection),
                "network_acl_deny": acl_deny,
                "has_tags":         bool(vault.tags),
            }
        ))
    return out


def scan_sql(cred, sub):
    if not SQL_OK:
        return None
    client = SqlManagementClient(cred, sub)
    out = []
    for srv in client.servers.list():
        tls = getattr(srv, "minimal_tls_version", "") or ""
        out.append(_result(srv.name, srv.location, f"v{srv.version}" if srv.version else "N/A", {
            "no_public_access": getattr(srv, "public_network_access", "Enabled") == "Disabled",
            "tls_1_2_plus":     tls in ("1.2", "1.3"),
            "has_tags":         bool(srv.tags),
        }))
    return out


def scan_aks(cred, sub):
    if not AKS_OK:
        return None
    client = ContainerServiceClient(cred, sub)
    out = []
    for cluster in client.managed_clusters.list():
        np = cluster.network_profile
        out.append(_result(
            cluster.name, cluster.location,
            f"k8s {cluster.kubernetes_version}" if cluster.kubernetes_version else "N/A", {
                "rbac_enabled":   bool(cluster.enable_rbac),
                "network_policy": bool(np and np.network_policy),
                "has_tags":       bool(cluster.tags),
            }
        ))
    return out


# ── service registry ──────────────────────────────────────────────────────────

SERVICE_CONFIG = [
    ("storage",   "Storage Accounts",        "&#128190;", scan_storage,   "SKU",
     [("no_public_blob", "No Public Blob"), ("https_only", "HTTPS Only"),
      ("tls_1_2_plus", "TLS 1.2+"), ("has_tags", "Tags")]),
    ("vms",       "Virtual Machines",        "&#128421;", scan_vms,       "Size / OS",
     [("managed_disk", "Managed Disk"), ("boot_diagnostics", "Boot Diag."),
      ("has_tags", "Tags")]),
    ("nsgs",      "Network Security Groups", "&#128274;", scan_nsgs,      "Rule Count",
     [("no_open_ssh", "No Open SSH"), ("no_open_rdp", "No Open RDP"),
      ("has_tags", "Tags")]),
    ("keyvaults", "Key Vaults",              "&#128477;", scan_keyvaults, "SKU",
     [("soft_delete", "Soft Delete"), ("purge_protection", "Purge Prot."),
      ("network_acl_deny", "ACL Deny"), ("has_tags", "Tags")]),
    ("sql",       "SQL Servers",             "&#128196;", scan_sql,       "Version",
     [("no_public_access", "No Public Access"), ("tls_1_2_plus", "TLS 1.2+"),
      ("has_tags", "Tags")]),
    ("aks",       "AKS Clusters",            "&#9096;",   scan_aks,       "K8s Version",
     [("rbac_enabled", "RBAC"), ("network_policy", "Net Policy"),
      ("has_tags", "Tags")]),
]


def build_services(cred, sub):
    services = []
    for sid, name, icon, scanner, detail_hdr, check_labels in SERVICE_CONFIG:
        try:
            resources = scanner(cred, sub)
            error = None
            if resources is None:
                resources = []
                error = INSTALL_HINT.get(sid, "Package not installed")
        except Exception as exc:
            resources = []
            error = str(exc)
        services.append({
            "id": sid, "name": name, "icon": icon,
            "detail_header": detail_hdr, "check_labels": check_labels,
            "resources": resources, "error": error,
        })
    return services


# ── HTML template ─────────────────────────────────────────────────────────────

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Azure CSPM Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: Segoe UI, Arial, sans-serif; background: #f0f2f5; color: #1a1a1a; }

    header {
      background: #0078d4; color: #fff;
      padding: 18px 32px;
      display: flex; justify-content: space-between; align-items: center;
    }
    header h1 { font-size: 1.35rem; font-weight: 600; }
    header .sub { font-size: 0.8rem; opacity: 0.85; margin-top: 3px; }
    .refresh-btn {
      color: #fff; text-decoration: none; font-size: 0.8rem;
      border: 1px solid rgba(255,255,255,.5); padding: 5px 14px; border-radius: 4px;
    }
    .refresh-btn:hover { background: rgba(255,255,255,.15); }

    .stats { display: flex; gap: 14px; padding: 20px 32px 0; flex-wrap: wrap; }
    .stat {
      background: #fff; border-radius: 6px; padding: 14px 22px;
      min-width: 140px; box-shadow: 0 1px 3px rgba(0,0,0,.1);
    }
    .stat .lbl { font-size: 0.72rem; color: #666; text-transform: uppercase; letter-spacing: .5px; }
    .stat .val { font-size: 1.9rem; font-weight: 700; margin-top: 4px; }
    .c-blue   { color: #0078d4; }
    .c-green  { color: #107c10; }
    .c-red    { color: #d13438; }
    .c-orange { color: #e07000; }

    .tabs {
      display: flex; margin: 20px 32px 0;
      border-bottom: 2px solid #ddd; overflow-x: auto;
    }
    .tab-btn {
      background: none; border: none; cursor: pointer;
      padding: 10px 16px; font-size: 0.84rem; color: #555;
      border-bottom: 3px solid transparent; margin-bottom: -2px;
      white-space: nowrap; display: flex; align-items: center; gap: 6px;
    }
    .tab-btn:hover { color: #0078d4; background: #f7f7f7; }
    .tab-btn.active { color: #0078d4; border-bottom-color: #0078d4; font-weight: 600; }
    .tbadge {
      background: #eee; color: #555; border-radius: 10px;
      padding: 1px 7px; font-size: 0.72rem; font-weight: 700;
    }
    .tab-btn.active .tbadge { background: #ddeeff; color: #0078d4; }

    .panel { display: none; padding: 20px 32px; }
    .panel.active { display: block; }

    .panel-head {
      display: flex; justify-content: space-between; align-items: center;
      margin-bottom: 14px;
    }
    .panel-head h2 { font-size: 1rem; font-weight: 600; color: #333; }
    .counters { display: flex; gap: 8px; }
    .counter {
      font-size: 0.78rem; font-weight: 600;
      padding: 3px 11px; border-radius: 12px;
    }
    .counter.g  { background: #dff6dd; color: #107c10; }
    .counter.r  { background: #fde7e9; color: #d13438; }
    .counter.gr { background: #eee; color: #777; }

    .warn {
      background: #fff4ce; border: 1px solid #f0c000;
      border-radius: 6px; padding: 10px 14px;
      font-size: 0.84rem; color: #6b4f00; margin-bottom: 14px;
    }

    table {
      width: 100%; border-collapse: collapse; background: #fff;
      border-radius: 6px; overflow: hidden;
      box-shadow: 0 1px 3px rgba(0,0,0,.1); font-size: 0.845rem;
    }
    th {
      background: #f7f7f7; text-align: left; padding: 10px 13px;
      font-weight: 600; border-bottom: 2px solid #e1e1e1;
      white-space: nowrap; color: #444;
    }
    td { padding: 9px 13px; border-bottom: 1px solid #f0f0f0; vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #fafbff; }

    .sbadge {
      display: inline-block; padding: 2px 9px; border-radius: 10px;
      font-size: 0.73rem; font-weight: 700;
    }
    .sbadge.ok  { background: #dff6dd; color: #107c10; }
    .sbadge.nok { background: #fde7e9; color: #d13438; }

    .chk { text-align: center; font-size: 1rem; }
    .chk.p { color: #107c10; }
    .chk.f { color: #d13438; }

    .score { font-weight: 700; font-size: 0.82rem; }
    .score.full { color: #107c10; }
    .score.part { color: #e07000; }
    .score.zero { color: #d13438; }

    .empty { text-align: center; padding: 36px; color: #999; }

    footer {
      padding: 14px 32px; font-size: 0.78rem; color: #888;
      border-top: 1px solid #e1e1e1; margin-top: 8px;
    }
    footer a { color: #0078d4; text-decoration: none; margin-right: 14px; }
    footer a:hover { text-decoration: underline; }
  </style>
</head>
<body>

<header>
  <div>
    <h1>Azure CSPM Dashboard</h1>
    <div class="sub">Subscription: {{ subscription_id }}</div>
  </div>
  <a class="refresh-btn" href="/">&#8635; Refresh</a>
</header>

<div class="stats">
  <div class="stat">
    <div class="lbl">Total Resources</div>
    <div class="val c-blue">{{ total_resources }}</div>
  </div>
  <div class="stat">
    <div class="lbl">Compliant</div>
    <div class="val c-green">{{ total_compliant }}</div>
  </div>
  <div class="stat">
    <div class="lbl">Non-Compliant</div>
    <div class="val c-red">{{ total_non_compliant }}</div>
  </div>
  <div class="stat">
    <div class="lbl">Compliance Rate</div>
    <div class="val {{ rate_class }}">{{ compliance_rate }}</div>
  </div>
</div>

<div class="tabs">
  {% for svc in services %}
  <button class="tab-btn" data-tab="{{ svc.id }}" onclick="showTab('{{ svc.id }}')">
    {{ svc.icon | safe }} {{ svc.name }}
    <span class="tbadge">{{ svc.resources | length }}</span>
  </button>
  {% endfor %}
</div>

{% for svc in services %}
{% set total_svc = svc.resources | length %}
{% set comp_svc  = svc.resources | selectattr('status', 'equalto', 'COMPLIANT') | list | length %}
<div class="panel" id="tab-{{ svc.id }}">

  <div class="panel-head">
    <h2>{{ svc.icon | safe }} {{ svc.name }}</h2>
    <div class="counters">
      {% if svc.error and total_svc == 0 %}
        <span class="counter gr">Unavailable</span>
      {% else %}
        <span class="counter g">{{ comp_svc }} Compliant</span>
        <span class="counter r">{{ total_svc - comp_svc }} Non-Compliant</span>
      {% endif %}
    </div>
  </div>

  {% if svc.error %}
  <div class="warn">&#9888; {{ svc.error }}</div>
  {% endif %}

  {% if svc.resources %}
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Name</th>
        <th>Location</th>
        <th>{{ svc.detail_header }}</th>
        <th>Status</th>
        <th>Score</th>
        {% for lbl in svc.check_labels %}
        <th>{{ lbl[1] }}</th>
        {% endfor %}
      </tr>
    </thead>
    <tbody>
      {% for r in svc.resources %}
      {% set parts = r.score.split('/') %}
      {% set p = parts[0] | int %}
      {% set t = parts[1] | int %}
      <tr>
        <td>{{ loop.index }}</td>
        <td><strong>{{ r.name }}</strong></td>
        <td>{{ r.location }}</td>
        <td>{{ r.detail }}</td>
        <td>
          <span class="sbadge {{ 'ok' if r.status == 'COMPLIANT' else 'nok' }}">
            {{ 'COMPLIANT' if r.status == 'COMPLIANT' else 'NON-COMPLIANT' }}
          </span>
        </td>
        <td>
          <span class="score {% if p == t %}full{% elif p == 0 %}zero{% else %}part{% endif %}">
            {{ r.score }}
          </span>
        </td>
        {% for lbl in svc.check_labels %}
        <td class="chk {{ 'p' if r.checks[lbl[0]] else 'f' }}">
          {{ '&#10003;' if r.checks[lbl[0]] else '&#10007;' }}
        </td>
        {% endfor %}
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% elif not svc.error %}
  <div class="empty">No {{ svc.name }} found in this subscription.</div>
  {% endif %}

</div>
{% endfor %}

<footer>
  <a href="/api/cspm/all">JSON: All Services</a>
  {% for svc in services %}
  <a href="/api/cspm/{{ svc.id }}">JSON: {{ svc.name }}</a>
  {% endfor %}
</footer>

<script>
  function showTab(id) {
    document.querySelectorAll('.panel').forEach(function(p) { p.classList.remove('active'); });
    document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    document.getElementById('tab-' + id).classList.add('active');
    document.querySelector('[data-tab="' + id + '"]').classList.add('active');
  }
  window.addEventListener('DOMContentLoaded', function() {
    var first = document.querySelector('.tab-btn');
    if (first) { showTab(first.getAttribute('data-tab')); }
  });
</script>
</body>
</html>"""


# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    if not SUBSCRIPTION_ID:
        return "<pre>Error: AZURE_SUBSCRIPTION_ID not set in .env</pre>", 500
    try:
        cred = DefaultAzureCredential()
        services = build_services(cred, SUBSCRIPTION_ID)
        total_r = sum(len(s["resources"]) for s in services)
        total_c = sum(
            sum(1 for r in s["resources"] if r["status"] == "COMPLIANT")
            for s in services
        )
        total_nc = total_r - total_c
        if total_r == 0:
            rate, rate_class = "N/A", "c-blue"
        else:
            pct = round(total_c / total_r * 100, 1)
            rate = f"{pct}%"
            rate_class = "c-green" if pct == 100 else ("c-orange" if pct >= 70 else "c-red")
        return render_template_string(
            TEMPLATE,
            subscription_id=SUBSCRIPTION_ID,
            services=services,
            total_resources=total_r,
            total_compliant=total_c,
            total_non_compliant=total_nc,
            compliance_rate=rate,
            rate_class=rate_class,
        )
    except Exception as exc:
        return f"<pre>Error: {exc}</pre>", 500


@app.route("/api/cspm/all")
def api_all():
    try:
        cred = DefaultAzureCredential()
        return jsonify(build_services(cred, SUBSCRIPTION_ID))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/cspm/<service_id>")
def api_service(service_id):
    scanner_map = {
        sid: scanner for sid, _, _, scanner, _, _ in SERVICE_CONFIG
    }
    if service_id not in scanner_map:
        return jsonify({"error": f"Unknown service '{service_id}'"}), 404
    try:
        cred = DefaultAzureCredential()
        resources = scanner_map[service_id](cred, SUBSCRIPTION_ID)
        if resources is None:
            return jsonify({"error": INSTALL_HINT.get(service_id, "Package not installed")}), 503
        return jsonify({"service": service_id, "total": len(resources), "resources": resources})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
