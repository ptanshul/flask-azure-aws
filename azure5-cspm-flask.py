import os
from flask import Flask, jsonify, render_template_string
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient

load_dotenv()

app = Flask(__name__)

SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")


def get_storage_client():
    if not SUBSCRIPTION_ID:
        raise ValueError("AZURE_SUBSCRIPTION_ID is missing from environment variables.")
    return StorageManagementClient(DefaultAzureCredential(), SUBSCRIPTION_ID)


def evaluate_storage_account(account):
    checks = {
        "public_blob_access_disabled": {
            "pass": account.allow_blob_public_access is False,
            "value": account.allow_blob_public_access,
            "description": "Blob public access should be disabled",
        },
        "https_only_enabled": {
            "pass": account.enable_https_traffic_only is True,
            "value": account.enable_https_traffic_only,
            "description": "HTTPS-only traffic should be enforced",
        },
        "minimum_tls_version_1_2": {
            "pass": str(account.minimum_tls_version) in ("TLS1_2", "TLS1_3"),
            "value": str(account.minimum_tls_version),
            "description": "Minimum TLS version should be 1.2 or higher",
        },
        "tags_present": {
            "pass": bool(account.tags),
            "value": account.tags or {},
            "description": "Resource should have tags for governance",
        },
    }

    passed = sum(1 for c in checks.values() if c["pass"])
    total = len(checks)
    status = "COMPLIANT" if passed == total else "NON_COMPLIANT"

    return {
        "name": account.name,
        "location": account.location,
        "sku": account.sku.name,
        "kind": account.kind,
        "blob_endpoint": account.primary_endpoints.blob,
        "status": status,
        "score": f"{passed}/{total}",
        "checks": checks,
    }


DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Azure CSPM Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: Segoe UI, Arial, sans-serif; background: #f0f2f5; color: #222; }

    header {
      background: #0078d4;
      color: #fff;
      padding: 20px 32px;
    }
    header h1 { font-size: 1.5rem; font-weight: 600; }
    header p  { font-size: 0.85rem; opacity: 0.85; margin-top: 4px; }

    .stats {
      display: flex;
      gap: 16px;
      padding: 24px 32px 0;
      flex-wrap: wrap;
    }
    .stat-card {
      background: #fff;
      border-radius: 6px;
      padding: 16px 24px;
      min-width: 160px;
      box-shadow: 0 1px 3px rgba(0,0,0,.1);
    }
    .stat-card .label { font-size: 0.75rem; color: #666; text-transform: uppercase; letter-spacing: .5px; }
    .stat-card .value { font-size: 2rem; font-weight: 700; margin-top: 4px; }
    .stat-card.green .value { color: #107c10; }
    .stat-card.red   .value { color: #d13438; }
    .stat-card.blue  .value { color: #0078d4; }

    .section { padding: 24px 32px; }
    .section h2 { font-size: 1rem; font-weight: 600; margin-bottom: 12px; color: #333; }

    table {
      width: 100%;
      border-collapse: collapse;
      background: #fff;
      border-radius: 6px;
      overflow: hidden;
      box-shadow: 0 1px 3px rgba(0,0,0,.1);
      font-size: 0.875rem;
    }
    th {
      background: #f7f7f7;
      text-align: left;
      padding: 10px 14px;
      font-weight: 600;
      border-bottom: 2px solid #e1e1e1;
      white-space: nowrap;
    }
    td { padding: 10px 14px; border-bottom: 1px solid #f0f0f0; vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #fafafa; }

    .badge {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: .3px;
    }
    .badge.compliant     { background: #dff6dd; color: #107c10; }
    .badge.non-compliant { background: #fde7e9; color: #d13438; }

    .check { display: inline-block; width: 20px; text-align: center; font-size: 1rem; }
    .check.pass { color: #107c10; }
    .check.fail { color: #d13438; }

    .score { font-weight: 600; }
    .score.full { color: #107c10; }
    .score.partial { color: #e07000; }
    .score.zero { color: #d13438; }

    .links { padding: 0 32px 24px; font-size: 0.8rem; color: #555; }
    .links a { color: #0078d4; text-decoration: none; margin-right: 16px; }
    .links a:hover { text-decoration: underline; }
  </style>
</head>
<body>

<header>
  <h1>Azure CSPM Dashboard &mdash; Storage Accounts</h1>
  <p>Subscription: {{ subscription_id }}</p>
</header>

<div class="stats">
  <div class="stat-card blue">
    <div class="label">Total Accounts</div>
    <div class="value">{{ total }}</div>
  </div>
  <div class="stat-card green">
    <div class="label">Compliant</div>
    <div class="value">{{ compliant }}</div>
  </div>
  <div class="stat-card red">
    <div class="label">Non-Compliant</div>
    <div class="value">{{ non_compliant }}</div>
  </div>
  <div class="stat-card {% if rate == '100.0%' %}green{% elif rate.split('.')[0]|int >= 50 %}blue{% else %}red{% endif %}">
    <div class="label">Compliance Rate</div>
    <div class="value">{{ rate }}</div>
  </div>
</div>

<div class="section">
  <h2>Storage Account Compliance</h2>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Account Name</th>
        <th>Location</th>
        <th>SKU</th>
        <th>Status</th>
        <th>Score</th>
        <th title="Blob public access disabled">No Public Blob</th>
        <th title="HTTPS only enforced">HTTPS Only</th>
        <th title="Min TLS 1.2+">TLS 1.2+</th>
        <th title="Tags present">Tags</th>
      </tr>
    </thead>
    <tbody>
      {% for a in accounts %}
      {% set passed = a.score.split('/')[0]|int %}
      {% set total_checks = a.score.split('/')[1]|int %}
      <tr>
        <td>{{ loop.index }}</td>
        <td><strong>{{ a.name }}</strong></td>
        <td>{{ a.location }}</td>
        <td>{{ a.sku }}</td>
        <td>
          {% if a.status == 'COMPLIANT' %}
            <span class="badge compliant">COMPLIANT</span>
          {% else %}
            <span class="badge non-compliant">NON-COMPLIANT</span>
          {% endif %}
        </td>
        <td>
          <span class="score {% if passed == total_checks %}full{% elif passed == 0 %}zero{% else %}partial{% endif %}">
            {{ a.score }}
          </span>
        </td>
        <td><span class="check {% if a.checks.public_blob_access_disabled.pass %}pass{% else %}fail{% endif %}">
          {% if a.checks.public_blob_access_disabled.pass %}&#10003;{% else %}&#10007;{% endif %}
        </span></td>
        <td><span class="check {% if a.checks.https_only_enabled.pass %}pass{% else %}fail{% endif %}">
          {% if a.checks.https_only_enabled.pass %}&#10003;{% else %}&#10007;{% endif %}
        </span></td>
        <td><span class="check {% if a.checks.minimum_tls_version_1_2.pass %}pass{% else %}fail{% endif %}">
          {% if a.checks.minimum_tls_version_1_2.pass %}&#10003;{% else %}&#10007;{% endif %}
        </span></td>
        <td><span class="check {% if a.checks.tags_present.pass %}pass{% else %}fail{% endif %}">
          {% if a.checks.tags_present.pass %}&#10003;{% else %}&#10007;{% endif %}
        </span></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<div class="links">
  <a href="/api/cspm/storage">JSON &rarr; Full Scan</a>
  <a href="/api/cspm/summary">JSON &rarr; Summary</a>
</div>

</body>
</html>
"""


@app.route("/", methods=["GET"])
def home():
    try:
        client = get_storage_client()
        accounts = [evaluate_storage_account(a) for a in client.storage_accounts.list()]
        compliant = sum(1 for a in accounts if a["status"] == "COMPLIANT")
        non_compliant = len(accounts) - compliant
        rate = f"{round(compliant / len(accounts) * 100, 1)}%" if accounts else "N/A"
        return render_template_string(
            DASHBOARD_TEMPLATE,
            subscription_id=SUBSCRIPTION_ID,
            accounts=accounts,
            total=len(accounts),
            compliant=compliant,
            non_compliant=non_compliant,
            rate=rate,
        )
    except Exception as err:
        return f"<pre>Error: {err}</pre>", 500


@app.route("/api/cspm/storage", methods=["GET"])
def cspm_storage():
    try:
        client = get_storage_client()
        results = [evaluate_storage_account(a) for a in client.storage_accounts.list()]
        return jsonify({
            "subscription_id": SUBSCRIPTION_ID,
            "total_accounts": len(results),
            "accounts": results,
        }), 200
    except Exception as err:
        return jsonify({"error": str(err)}), 500


@app.route("/api/cspm/summary", methods=["GET"])
def cspm_summary():
    try:
        client = get_storage_client()
        accounts = [evaluate_storage_account(a) for a in client.storage_accounts.list()]

        compliant = [a for a in accounts if a["status"] == "COMPLIANT"]
        non_compliant = [a for a in accounts if a["status"] == "NON_COMPLIANT"]

        check_failures = {}
        for account in accounts:
            for check_name, check in account["checks"].items():
                if not check["pass"]:
                    check_failures[check_name] = check_failures.get(check_name, 0) + 1

        return jsonify({
            "subscription_id": SUBSCRIPTION_ID,
            "total_accounts": len(accounts),
            "compliant": len(compliant),
            "non_compliant": len(non_compliant),
            "compliance_rate": f"{round(len(compliant) / len(accounts) * 100, 1)}%" if accounts else "N/A",
            "top_failures": check_failures,
            "non_compliant_accounts": [a["name"] for a in non_compliant],
        }), 200
    except Exception as err:
        return jsonify({"error": str(err)}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
