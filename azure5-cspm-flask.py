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


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Azure CSPM API",
        "routes": {
            "storage_scan": "/api/cspm/storage",
            "summary":      "/api/cspm/summary",
        }
    })


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
