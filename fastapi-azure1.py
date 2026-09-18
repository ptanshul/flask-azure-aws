"""
CWPP (Cloud Workload Protection Platform) on Azure via FastAPI
Uses Microsoft Defender for Cloud (azure-mgmt-security).

Required packages:
    pip install fastapi uvicorn azure-identity azure-mgmt-security azure-mgmt-resource

Authentication (set env vars before running):
    AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID
"""

import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.security import SecurityCenter
from azure.mgmt.security.models import Pricing, SecurityContact, AutoProvisioningSetting
from azure.core.exceptions import AzureError

app = FastAPI(title="Azure CWPP API", description="Manage Cloud Workload Protection via Microsoft Defender for Cloud")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_subscription_id() -> str:
    sub = os.environ.get("AZURE_SUBSCRIPTION_ID")
    if not sub:
        raise HTTPException(status_code=500, detail="AZURE_SUBSCRIPTION_ID env var not set")
    return sub


def get_credential():
    tenant = os.environ.get("AZURE_TENANT_ID")
    client = os.environ.get("AZURE_CLIENT_ID")
    secret = os.environ.get("AZURE_CLIENT_SECRET")
    if tenant and client and secret:
        return ClientSecretCredential(tenant_id=tenant, client_id=client, client_secret=secret)
    return DefaultAzureCredential()


def get_client() -> SecurityCenter:
    return SecurityCenter(credential=get_credential(), subscription_id=get_subscription_id())


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class EnablePlanRequest(BaseModel):
    plan_name: str   # e.g. VirtualMachines, SqlServers, AppServices, Containers, KeyVaults, Dns, Arm, StorageAccounts
    pricing_tier: str = "Standard"  # Standard = paid/protected, Free = off


class SecurityContactRequest(BaseModel):
    email: str
    phone: str = ""
    alert_notifications: str = "On"   # On | Off
    alerts_to_admins: str = "On"      # On | Off


class AutoProvisionRequest(BaseModel):
    setting_name: str = "mma-agent"   # mma-agent = Microsoft Monitoring Agent
    auto_provision: str = "On"        # On | Off


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
def home():
    return {"message": "Azure CWPP API", "docs": "/docs"}


@app.get("/cwpp/plans", summary="List all Defender pricing plans and their current tier")
def list_plans():
    """Returns every Defender for Cloud plan and whether it is Free or Standard (paid)."""
    try:
        client = get_client()
        plans = list(client.pricings.list(scope=f"/subscriptions/{get_subscription_id()}").value)
        return [
            {"name": p.name, "pricing_tier": p.pricing_tier, "free_trial_remaining_time": str(p.free_trial_remaining_time)}
            for p in plans
        ]
    except AzureError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/cwpp/enable-plan", summary="Enable or disable a specific Defender plan")
def enable_plan(req: EnablePlanRequest):
    """
    Enable (Standard) or disable (Free) a Defender for Cloud workload protection plan.

    Common plan_name values:
      VirtualMachines, SqlServers, AppServices, Containers,
      KeyVaults, Dns, Arm, StorageAccounts, SqlServerVirtualMachines
    """
    try:
        client = get_client()
        sub_id = get_subscription_id()
        scope = f"/subscriptions/{sub_id}"
        pricing = Pricing(pricing_tier=req.pricing_tier)
        result = client.pricings.update(scope=scope, pricing_name=req.plan_name, pricing=pricing)
        return {
            "plan": result.name,
            "pricing_tier": result.pricing_tier,
            "status": "updated",
        }
    except AzureError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/cwpp/alerts", summary="Get active security alerts")
def get_alerts(location: str = "eastus"):
    """Fetch all active Microsoft Defender for Cloud security alerts for a given location."""
    try:
        client = get_client()
        alerts = list(client.alerts.list_by_subscription())
        return [
            {
                "alert_name": a.alert_display_name,
                "severity": a.severity,
                "status": a.status,
                "description": a.description,
                "compromised_entity": a.compromised_entity,
                "time_generated": str(a.time_generated_utc),
            }
            for a in alerts
        ]
    except AzureError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/cwpp/assessments", summary="Get security assessments / recommendations")
def get_assessments():
    """Lists all security health assessments (recommendations) for the subscription."""
    try:
        client = get_client()
        items = list(client.assessments.list(scope=f"/subscriptions/{get_subscription_id()}"))
        return [
            {
                "name": a.display_name,
                "status": a.status.code if a.status else None,
                "severity": a.metadata.severity if a.metadata else None,
                "resource_id": a.resource_details.id if a.resource_details else None,
            }
            for a in items
        ]
    except AzureError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/cwpp/secure-score", summary="Get Secure Score for the subscription")
def get_secure_score():
    """Returns the Microsoft Defender for Cloud Secure Score."""
    try:
        client = get_client()
        score = client.secure_scores.get(secure_score_name="ascScore")
        return {
            "display_name": score.display_name,
            "current_score": score.score.current if score.score else None,
            "max_score": score.score.max if score.score else None,
            "percentage": score.score.percentage if score.score else None,
        }
    except AzureError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/cwpp/security-contact", summary="Set security contact for alerts")
def set_security_contact(req: SecurityContactRequest):
    """Configure the email/phone that receives Defender security alert notifications."""
    try:
        client = get_client()
        contact = SecurityContact(
            email=req.email,
            phone=req.phone,
            alert_notifications=req.alert_notifications,
            alerts_to_admins=req.alerts_to_admins,
        )
        result = client.security_contacts.create(security_contact_name="default1", security_contact=contact)
        return {
            "name": result.name,
            "email": result.email,
            "phone": result.phone,
            "alert_notifications": result.alert_notifications,
        }
    except AzureError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/cwpp/security-contact", summary="Get current security contact configuration")
def get_security_contact():
    """Returns the currently configured security alert contact."""
    try:
        client = get_client()
        result = client.security_contacts.get(security_contact_name="default1")
        return {
            "name": result.name,
            "email": result.email,
            "phone": result.phone,
            "alert_notifications": result.alert_notifications,
            "alerts_to_admins": result.alerts_to_admins,
        }
    except AzureError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/cwpp/auto-provisioning", summary="Enable or disable auto-provisioning of monitoring agents")
def set_auto_provisioning(req: AutoProvisionRequest):
    """
    Toggle auto-provisioning for Defender monitoring agents on VMs.
    setting_name: mma-agent (Log Analytics Agent)
    auto_provision: On | Off
    """
    try:
        client = get_client()
        setting = AutoProvisioningSetting(auto_provision=req.auto_provision)
        result = client.auto_provisioning_settings.create(
            auto_provisioning_setting_name=req.setting_name,
            setting=setting,
        )
        return {"setting_name": result.name, "auto_provision": result.auto_provision}
    except AzureError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/cwpp/auto-provisioning", summary="List auto-provisioning settings")
def list_auto_provisioning():
    """Returns all auto-provisioning settings (e.g. agent deployment on VMs)."""
    try:
        client = get_client()
        settings = list(client.auto_provisioning_settings.list())
        return [{"name": s.name, "auto_provision": s.auto_provision} for s in settings]
    except AzureError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/cwpp/tasks", summary="Get remediation tasks (actionable recommendations)")
def get_tasks():
    """Lists all pending security remediation tasks from Defender for Cloud."""
    try:
        client = get_client()
        tasks = list(client.tasks.list())
        return [
            {
                "task_name": t.name,
                "security_task_parameters": t.security_task_parameters.additional_properties if t.security_task_parameters else {},
                "state": t.state,
                "creation_time": str(t.creation_time_utc),
            }
            for t in tasks
        ]
    except AzureError as e:
        raise HTTPException(status_code=500, detail=str(e))
