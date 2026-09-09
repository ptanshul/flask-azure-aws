import os
from flask import Flask, jsonify
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.containerservice import ContainerServiceClient

load_dotenv()

app = Flask(__name__)

SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")


def get_aks_client():
    if not SUBSCRIPTION_ID:
        raise ValueError("AZURE_SUBSCRIPTION_ID is missing from .env.")
    credential = DefaultAzureCredential()
    return ContainerServiceClient(credential, SUBSCRIPTION_ID)


@app.route("/api/aks", methods=["GET"])
def list_aks_clusters():
    try:
        client = get_aks_client()
        clusters = []

        # List all managed clusters across the subscription
        for cluster in client.managed_clusters.list():
            clusters.append({
                "name": cluster.name,
                "resource_group": cluster.id.split("/")[4],
                "location": cluster.location,
                "kubernetes_version": cluster.kubernetes_version,
                "provisioning_state": cluster.provisioning_state,
                "node_resource_group": cluster.node_resource_group,
            })

        return jsonify({
            "subscription_id": SUBSCRIPTION_ID,
            "total_count": len(clusters),
            "clusters": clusters,
        }), 200

    except Exception as err:
        return jsonify({"error": str(err)}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)