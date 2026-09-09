import os
from flask import Flask, render_template_string, jsonify
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential

try:
    from azure.mgmt.security import SecurityCenter
    SECURITY_OK = True
except ImportError:
    SECURITY_OK = False

load_dotenv()
app = Flask(__name__)
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")

PLAN_LABELS = {
    "VirtualMachines":              "Virtual Machines",
    "SqlServers":                   "SQL Servers (Azure)",
    "SqlServerVirtualMachines":     "SQL Servers (VMs)",
    "AppServices":                  "App Services",
    "StorageAccounts":              "Storage Accounts",
    "Containers":                   "Containers / AKS",
    "KeyVaults":                    "Key Vaults",
    "Arm":                          "Azure Resource Manager",
    "Dns":                          "DNS",
    "OpenSourceRelationalDatabases":"OSS Relational DBs",
    "CosmosDbs":                    "Cosmos DB",
    "Api":                          "API Management",
}

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
SEVERITY_CSS   = {"High": "sev-high", "Medium": "sev-medium",
                  "Low": "sev-low",   "Informational": "sev-info"}


# ── client ────────────────────────────────────────────────────────────────────

def get_client():
    if not SECURITY_OK:
        raise RuntimeError("Run: pip install azure-mgmt-security")
    if not SUBSCRIPTION_ID:
        raise RuntimeError("AZURE_SUBSCRIPTION_ID not set in .env")
    cred = DefaultAzureCredential()
    try:
        return SecurityCenter(credential=cred, subscription_id=SUBSCRIPTION_ID)
    except TypeError:
        return SecurityCenter(credential=cred, subscription_id=SUBSCRIPTION_ID,
                              asc_location="eastus")


# ── scanners ──────────────────────────────────────────────────────────────────

def scan_defender_plans(client):
    plans = []
    for p in client.pricings.list():
        enabled = p.pricing_tier == "Standard"
        plans.append({
            "id":      p.name,
            "name":    PLAN_LABELS.get(p.name, p.name),
            "tier":    p.pricing_tier,
            "enabled": enabled,
            "status":  "PROTECTED" if enabled else "UNPROTECTED",
        })
    return sorted(plans, key=lambda x: (not x["enabled"], x["name"]))


def scan_alerts(client):
    out = []
    for a in client.alerts.list():
        status = getattr(a, "status", "Active") or "Active"
        if status in ("Dismissed", "Resolved"):
            continue
        sev = getattr(a, "severity", "Informational") or "Informational"
        name = (getattr(a, "alert_display_name", "") or
                getattr(a, "alert_type", "Unknown Alert"))
        time_val = (getattr(a, "time_generated_utc", None) or
                    getattr(a, "start_time_utc", None))
        out.append({
            "name":          name,
            "severity":      sev,
            "sev_order":     SEVERITY_ORDER.get(sev, 99),
            "sev_css":       SEVERITY_CSS.get(sev, "sev-info"),
            "resource":      getattr(a, "compromised_entity", "N/A") or "N/A",
            "alert_type":    getattr(a, "alert_type", "") or "",
            "time":          str(time_val)[:19] if time_val else "N/A",
            "description":   (getattr(a, "description", "") or "")[:220],
            "status":        status,
        })
    return sorted(out, key=lambda x: x["sev_order"])


def scan_assessments(client):
    scope = f"/subscriptions/{SUBSCRIPTION_ID}"
    out = []
    count = 0
    for a in client.assessments.list(scope=scope):
        if count >= 150:
            break
        status_obj = getattr(a, "status", None)
        code = getattr(status_obj, "code", "NotApplicable") if status_obj else "NotApplicable"
        if code != "Unhealthy":
            continue
        meta       = getattr(a, "metadata", None)
        sev        = getattr(meta, "severity", "Medium") if meta else "Medium"
        category   = getattr(meta, "category", "General") if meta else "General"
        remediation = getattr(meta, "remediation_description", "") if meta else ""
        display    = (getattr(a, "display_name", "") or
                      (a.name or "Unknown Assessment"))
        rid        = a.id or ""
        resource   = rid.split("/")[-1] if "/" in rid else rid
        out.append({
            "name":        display,
            "severity":    sev,
            "sev_order":   SEVERITY_ORDER.get(sev, 99),
            "sev_css":     SEVERITY_CSS.get(sev, "sev-info"),
            "category":    category,
            "resource":    resource,
            "remediation": (remediation or "")[:160],
        })
        count += 1
    return sorted(out, key=lambda x: x["sev_order"])


def scan_secure_scores(client):
    scores = []
    for s in client.secure_scores.list():
        cur = max_s = pct = 0
        if hasattr(s, "score") and s.score:
            cur   = round(s.score.current or 0, 2)
            max_s = round(s.score.max or 0, 2)
            pct   = round(cur / max_s * 100, 1) if max_s else 0
        scores.append({
            "id":      s.name,
            "name":    getattr(s, "display_name", s.name) or s.name,
            "current": cur,
            "max":     max_s,
            "pct":     pct,
        })
    return scores


def scan_score_controls(client):
    out = []
    for c in client.secure_score_controls.list():
        cur = max_s = pct = 0
        if hasattr(c, "score") and c.score:
            cur   = round(c.score.current or 0, 2)
            max_s = round(c.score.max or 0, 2)
            pct   = round(cur / max_s * 100, 1) if max_s else 0
        out.append({
            "name":      getattr(c, "display_name", c.name or "") or c.name or "–",
            "current":   cur,
            "max":       max_s,
            "pct":       pct,
            "healthy":   getattr(c, "healthy_resource_count",   0) or 0,
            "unhealthy": getattr(c, "unhealthy_resource_count", 0) or 0,
        })
    return sorted(out, key=lambda x: x["pct"])


# ── HTML template ─────────────────────────────────────────────────────────────

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Azure CWPP Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: Segoe UI, Arial, sans-serif; background: #f0f2f5; color: #1a1a1a; }

    header {
      background: #1a1a2e; color: #fff;
      padding: 18px 32px;
      display: flex; justify-content: space-between; align-items: center;
    }
    header h1 { font-size: 1.35rem; font-weight: 600; }
    header .sub { font-size: 0.8rem; opacity: 0.7; margin-top: 3px; }

    .header-right { display: flex; align-items: center; gap: 14px; }

    .hcard {
      border-radius: 10px; padding: 10px 20px; text-align: center; min-width: 120px;
      border: 1px solid rgba(255,255,255,0.15);
    }
    .hcard.score  { background: rgba(255,255,255,0.1); }
    .hcard.danger { background: rgba(209,52,56,0.2); border-color: rgba(209,52,56,0.4); }
    .hcard .hc-title { font-size: 0.6rem; text-transform: uppercase; letter-spacing: 1.2px; opacity: 0.75; margin-bottom: 4px; }
    .hcard .hc-val   { font-size: 2.2rem; font-weight: 800; line-height: 1; }
    .hcard.score  .hc-val   { color: #a8e6a3; }
    .hcard.danger .hc-val   { color: #ff6b6b; }
    .hcard .hc-sub   { font-size: 0.65rem; opacity: 0.75; margin-top: 3px; }

    .refresh-btn {
      color: #fff; text-decoration: none; font-size: 0.8rem;
      border: 1px solid rgba(255,255,255,.35); padding: 5px 14px; border-radius: 4px;
    }
    .refresh-btn:hover { background: rgba(255,255,255,.1); }

    .stats { display: flex; gap: 14px; padding: 20px 32px 0; flex-wrap: wrap; }
    .stat {
      background: #fff; border-radius: 6px; padding: 14px 22px;
      min-width: 140px; box-shadow: 0 1px 3px rgba(0,0,0,.1);
    }
    .stat .lbl { font-size: 0.72rem; color: #666; text-transform: uppercase; letter-spacing: .5px; }
    .stat .val { font-size: 1.9rem; font-weight: 700; margin-top: 4px; }
    .c-dark   { color: #1a1a2e; }
    .c-green  { color: #107c10; }
    .c-red    { color: #d13438; }
    .c-orange { color: #e07000; }
    .c-blue   { color: #0078d4; }

    .tabs {
      display: flex; margin: 20px 32px 0;
      border-bottom: 2px solid #ddd; overflow-x: auto;
    }
    .tab-btn {
      background: none; border: none; cursor: pointer;
      padding: 10px 18px; font-size: 0.84rem; color: #555;
      border-bottom: 3px solid transparent; margin-bottom: -2px;
      white-space: nowrap; display: flex; align-items: center; gap: 6px;
    }
    .tab-btn:hover { color: #1a1a2e; background: #f5f5f5; }
    .tab-btn.active { color: #1a1a2e; border-bottom-color: #1a1a2e; font-weight: 600; }
    .tbadge {
      background: #eee; color: #555; border-radius: 10px;
      padding: 1px 7px; font-size: 0.72rem; font-weight: 700;
    }
    .tab-btn.active .tbadge { background: #e0e0ee; color: #1a1a2e; }

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
    .counter.o  { background: #fff4ce; color: #8a5700; }
    .counter.b  { background: #ddeeff; color: #0055aa; }

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

    .badge { display: inline-block; padding: 2px 10px; border-radius: 10px; font-size: 0.73rem; font-weight: 700; }
    .badge.ok  { background: #dff6dd; color: #107c10; }
    .badge.nok { background: #fde7e9; color: #d13438; }

    .sev { display: inline-block; padding: 2px 9px; border-radius: 10px; font-size: 0.73rem; font-weight: 700; }
    .sev-high   { background: #fde7e9; color: #d13438; }
    .sev-medium { background: #fff4ce; color: #8a5700; }
    .sev-low    { background: #dff6dd; color: #107c10; }
    .sev-info   { background: #ddeeff; color: #0078d4; }

    .prog-wrap { background: #eee; border-radius: 6px; height: 8px; width: 130px; overflow: hidden; display: inline-block; vertical-align: middle; margin-right: 8px; }
    .prog-bar  { height: 100%; border-radius: 6px; }
    .pg-green  { background: #107c10; }
    .pg-orange { background: #e07000; }
    .pg-red    { background: #d13438; }

    .score-cards { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px; }
    .score-card {
      background: #fff; border-radius: 8px; padding: 20px 28px;
      box-shadow: 0 1px 3px rgba(0,0,0,.1); text-align: center; min-width: 180px;
    }
    .score-card .sc-name { font-size: 0.8rem; color: #666; margin-bottom: 8px; }
    .score-card .sc-val  { font-size: 2.8rem; font-weight: 800; line-height: 1; }
    .score-card .sc-sub  { font-size: 0.8rem; color: #999; margin-top: 6px; }

    .empty { text-align: center; padding: 40px; color: #aaa; font-size: 0.9rem; }
    .err   { background: #fde7e9; border: 1px solid #f1b0b4; border-radius: 6px;
             padding: 12px 16px; color: #8c0009; font-size: 0.85rem; margin: 20px 32px; }

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
    <h1>&#128737; Azure CWPP Dashboard</h1>
    <div class="sub">Cloud Workload Protection Platform &nbsp;|&nbsp; Subscription: {{ subscription_id }}</div>
  </div>
  <div class="header-right">
    <div class="hcard score">
      <div class="hc-title">Secure Score</div>
      <div class="hc-val">{{ secure_score_pct }}%</div>
      <div class="hc-sub">{{ secure_score_pts }} / {{ secure_score_max }} pts</div>
    </div>
    <div class="hcard danger">
      <div class="hc-title">High Alerts</div>
      <div class="hc-val">{{ high_alerts }}</div>
      <div class="hc-sub">Active / Unresolved</div>
    </div>
    <a class="refresh-btn" href="/">&#8635; Refresh</a>
  </div>
</header>

<div class="stats">
  <div class="stat">
    <div class="lbl">Defender Plans</div>
    <div class="val c-dark">{{ plans_enabled }}/{{ plans_total }}</div>
  </div>
  <div class="stat">
    <div class="lbl">Total Alerts</div>
    <div class="val c-red">{{ total_alerts }}</div>
  </div>
  <div class="stat">
    <div class="lbl">High Severity</div>
    <div class="val c-red">{{ high_alerts }}</div>
  </div>
  <div class="stat">
    <div class="lbl">Medium Severity</div>
    <div class="val c-orange">{{ medium_alerts }}</div>
  </div>
  <div class="stat">
    <div class="lbl">Failed Checks</div>
    <div class="val c-orange">{{ total_assessments }}</div>
  </div>
  <div class="stat">
    <div class="lbl">Secure Score</div>
    <div class="val {{ 'c-green' if secure_score_pct >= 80 else ('c-orange' if secure_score_pct >= 50 else 'c-red') }}">{{ secure_score_pct }}%</div>
  </div>
</div>

<div class="tabs">
  <button class="tab-btn" data-tab="plans" onclick="showTab('plans')">
    &#128737; Defender Plans <span class="tbadge">{{ plans | length }}</span>
  </button>
  <button class="tab-btn" data-tab="alerts" onclick="showTab('alerts')">
    &#9888; Security Alerts <span class="tbadge">{{ alerts | length }}</span>
  </button>
  <button class="tab-btn" data-tab="recommendations" onclick="showTab('recommendations')">
    &#128203; Recommendations <span class="tbadge">{{ assessments | length }}</span>
  </button>
  <button class="tab-btn" data-tab="score" onclick="showTab('score')">
    &#127919; Secure Score <span class="tbadge">{{ controls | length }}</span>
  </button>
</div>

<!-- ── DEFENDER PLANS ─────────────────────────────────────────────────────── -->
<div class="panel" id="tab-plans">
  <div class="panel-head">
    <h2>&#128737; Defender for Cloud — Workload Protection Plans</h2>
    <div class="counters">
      <span class="counter g">{{ plans_enabled }} Protected</span>
      <span class="counter r">{{ plans_total - plans_enabled }} Unprotected</span>
    </div>
  </div>
  {% if plans %}
  <table>
    <thead>
      <tr><th>#</th><th>Workload</th><th>Plan ID</th><th>Tier</th><th>Protection Status</th></tr>
    </thead>
    <tbody>
      {% for p in plans %}
      <tr>
        <td>{{ loop.index }}</td>
        <td><strong>{{ p.name }}</strong></td>
        <td style="color:#888;font-size:0.8rem;">{{ p.id }}</td>
        <td>{{ p.tier }}</td>
        <td>
          <span class="badge {{ 'ok' if p.enabled else 'nok' }}">
            {{ '&#10003; PROTECTED' if p.enabled else '&#10007; UNPROTECTED' }}
          </span>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">No Defender plans returned. Verify SecurityReader permissions.</div>
  {% endif %}
</div>

<!-- ── SECURITY ALERTS ───────────────────────────────────────────────────── -->
<div class="panel" id="tab-alerts">
  <div class="panel-head">
    <h2>&#9888; Active Security Alerts</h2>
    <div class="counters">
      <span class="counter r">{{ high_alerts }} High</span>
      <span class="counter o">{{ medium_alerts }} Medium</span>
      <span class="counter b">{{ low_alerts }} Low</span>
    </div>
  </div>
  {% if alerts %}
  <table>
    <thead>
      <tr>
        <th>#</th><th>Severity</th><th>Alert Name</th>
        <th>Affected Resource</th><th>Detected (UTC)</th><th>Description</th>
      </tr>
    </thead>
    <tbody>
      {% for a in alerts %}
      <tr>
        <td>{{ loop.index }}</td>
        <td><span class="sev {{ a.sev_css }}">{{ a.severity }}</span></td>
        <td><strong>{{ a.name }}</strong></td>
        <td style="font-size:0.82rem;color:#555;">{{ a.resource }}</td>
        <td style="font-size:0.78rem;color:#888;white-space:nowrap;">{{ a.time }}</td>
        <td style="font-size:0.8rem;color:#555;max-width:300px;">{{ a.description }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">&#10003; No active alerts — environment looks clean.</div>
  {% endif %}
</div>

<!-- ── RECOMMENDATIONS ──────────────────────────────────────────────────── -->
<div class="panel" id="tab-recommendations">
  <div class="panel-head">
    <h2>&#128203; Failed Security Assessments</h2>
    <div class="counters">
      {% set high_a  = assessments | selectattr('severity', 'equalto', 'High')   | list | length %}
      {% set med_a   = assessments | selectattr('severity', 'equalto', 'Medium') | list | length %}
      <span class="counter r">{{ high_a }} High</span>
      <span class="counter o">{{ med_a }} Medium</span>
    </div>
  </div>
  {% if assessments %}
  <table>
    <thead>
      <tr>
        <th>#</th><th>Severity</th><th>Recommendation</th>
        <th>Category</th><th>Resource</th><th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      {% for a in assessments %}
      <tr>
        <td>{{ loop.index }}</td>
        <td><span class="sev {{ a.sev_css }}">{{ a.severity }}</span></td>
        <td><strong>{{ a.name }}</strong></td>
        <td style="font-size:0.8rem;color:#555;">{{ a.category }}</td>
        <td style="font-size:0.8rem;color:#888;">{{ a.resource }}</td>
        <td style="font-size:0.78rem;color:#555;max-width:260px;">{{ a.remediation }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">&#10003; No failed assessments found.</div>
  {% endif %}
</div>

<!-- ── SECURE SCORE ─────────────────────────────────────────────────────── -->
<div class="panel" id="tab-score">
  <div class="panel-head">
    <h2>&#127919; Secure Score — Control Breakdown</h2>
    <div class="counters">
      {% set hi_c = controls | selectattr('pct', 'ge', 80) | list | length %}
      {% set lo_c = controls | selectattr('pct', 'lt', 80) | list | length %}
      <span class="counter g">{{ hi_c }} Strong</span>
      <span class="counter r">{{ lo_c }} Need Work</span>
    </div>
  </div>

  <div class="score-cards">
    {% for s in scores %}
    {% set color = 'c-green' if s.pct >= 80 else ('c-orange' if s.pct >= 50 else 'c-red') %}
    <div class="score-card">
      <div class="sc-name">{{ s.name }}</div>
      <div class="sc-val {{ color }}">{{ s.pct }}%</div>
      <div class="sc-sub">{{ s.current }} / {{ s.max }} pts</div>
    </div>
    {% endfor %}
  </div>

  {% if controls %}
  <table>
    <thead>
      <tr>
        <th>#</th><th>Security Control</th><th>Score</th>
        <th>Progress</th><th>Healthy</th><th>Unhealthy</th>
      </tr>
    </thead>
    <tbody>
      {% for c in controls %}
      {% set pct = c.pct %}
      {% set pg  = 'pg-green' if pct >= 80 else ('pg-orange' if pct >= 50 else 'pg-red') %}
      {% set fc  = '#107c10'  if pct >= 80 else ('#e07000'   if pct >= 50 else '#d13438') %}
      <tr>
        <td>{{ loop.index }}</td>
        <td><strong>{{ c.name }}</strong></td>
        <td style="font-weight:700;color:{{ fc }};">{{ pct }}%</td>
        <td>
          <div class="prog-wrap">
            <div class="prog-bar {{ pg }}" style="width:{{ pct }}%"></div>
          </div>
          <span style="font-size:0.8rem;color:#666;">{{ c.current }} / {{ c.max }} pts</span>
        </td>
        <td style="color:#107c10;font-weight:600;">{{ c.healthy }}</td>
        <td style="color:#d13438;font-weight:600;">{{ c.unhealthy }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">Secure Score controls unavailable.</div>
  {% endif %}
</div>

<footer>
  <a href="/api/plans">JSON: Defender Plans</a>
  <a href="/api/alerts">JSON: Alerts</a>
  <a href="/api/recommendations">JSON: Recommendations</a>
  <a href="/api/score">JSON: Secure Score</a>
</footer>

<script>
  function showTab(id) {
    document.querySelectorAll('.panel').forEach(function(p) { p.classList.remove('active'); });
    document.querySelectorAll('.tab-btn').forEach(function(b) { b.classList.remove('active'); });
    document.getElementById('tab-' + id).classList.add('active');
    document.querySelector('[data-tab="' + id + '"]').classList.add('active');
  }
  window.addEventListener('DOMContentLoaded', function() { showTab('plans'); });
</script>
</body>
</html>"""


# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    if not SECURITY_OK:
        return ("<div style='font-family:monospace;padding:32px'>"
                "<b>Missing package.</b><br>Run: <code>pip install azure-mgmt-security</code>"
                "</div>"), 500
    try:
        client = get_client()
        plans       = scan_defender_plans(client)
        alerts      = scan_alerts(client)
        scores      = scan_secure_scores(client)
        controls    = scan_score_controls(client)
        assessments = scan_assessments(client)

        plans_enabled  = sum(1 for p in plans if p["enabled"])
        high_alerts    = sum(1 for a in alerts if a["severity"] == "High")
        medium_alerts  = sum(1 for a in alerts if a["severity"] == "Medium")
        low_alerts     = sum(1 for a in alerts if a["severity"] == "Low")

        main = next((s for s in scores if s["id"] == "ascScore"), scores[0] if scores else None)
        sec_pct = main["pct"]     if main else 0
        sec_pts = main["current"] if main else 0
        sec_max = main["max"]     if main else 0

        return render_template_string(
            TEMPLATE,
            subscription_id=SUBSCRIPTION_ID,
            plans=plans,
            alerts=alerts,
            assessments=assessments,
            scores=scores,
            controls=controls,
            plans_enabled=plans_enabled,
            plans_total=len(plans),
            total_alerts=len(alerts),
            high_alerts=high_alerts,
            medium_alerts=medium_alerts,
            low_alerts=low_alerts,
            total_assessments=len(assessments),
            secure_score_pct=sec_pct,
            secure_score_pts=sec_pts,
            secure_score_max=sec_max,
        )
    except Exception as exc:
        return f"<pre style='padding:32px'>Error: {exc}</pre>", 500


@app.route("/api/plans")
def api_plans():
    try:
        return jsonify(scan_defender_plans(get_client()))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/alerts")
def api_alerts():
    try:
        return jsonify(scan_alerts(get_client()))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/recommendations")
def api_recommendations():
    try:
        return jsonify(scan_assessments(get_client()))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/score")
def api_score():
    try:
        client = get_client()
        return jsonify({
            "secure_scores": scan_secure_scores(client),
            "controls":      scan_score_controls(client),
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
