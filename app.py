import os
from flask import Flask, jsonify
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient

load_dotenv()

app = Flask(__name__)

SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")

def get_resource_client():
    if not SUBSCRIPTION_ID:
        raise ValueError("AZURE_SUBSCRIPTION_ID is missing from environment variables.")
    credential = DefaultAzureCredential()
    return ResourceManagementClient(credential, SUBSCRIPTION_ID)

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Azure Resource Explorer API",
        "routes": {
            "all_resources": "/api/resources",
            "resource_groups": "/api/resource-groups"
        }
    })

@app.route("/api/resources", methods=["GET"])
def list_resources():
    try:
        client = get_resource_client()
        resource_list = []
        for item in client.resources.list():
            resource_list.append({
                "id": item.id,
                "name": item.name,
                "type": item.type,
                "location": item.location,
                "tags": item.tags or {}
            })
        return jsonify({
            "subscription_id": SUBSCRIPTION_ID,
            "total_count": len(resource_list),
            "resources": resource_list
        }), 200
    except Exception as err:
        return jsonify({"error": str(err)}), 500

@app.route("/api/resource-groups", methods=["GET"])
def list_resource_groups():
    try:
        client = get_resource_client()
        rg_list = [
            {"name": rg.name, "location": rg.location, "tags": rg.tags or {}}
            for rg in client.resource_groups.list()
        ]
        return jsonify({
            "subscription_id": SUBSCRIPTION_ID,
            "total_count": len(rg_list),
            "resource_groups": rg_list
        }), 200
    except Exception as err:
        return jsonify({"error": str(err)}), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
