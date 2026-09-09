import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from dotenv import load_dotenv

load_dotenv()

client = StorageManagementClient(
    DefaultAzureCredential(), os.getenv("AZURE_SUBSCRIPTION_ID")
)

for account in client.storage_accounts.list():
  print("=" * 60)
  print(f"Name:             {account.name}")
  print(f"Location:         {account.location}")
  print(f"SKU (Redundancy): {account.sku.name}")
  print(f"Kind:             {account.kind}")
  print(f"Blob Endpoint:    {account.primary_endpoints.blob}")
  print(f"HTTPS Enforced:   {account.enable_https_traffic_only}")
  print(f"Min TLS Version:  {account.minimum_tls_version}")
  print(f"Public Access:    {account.allow_blob_public_access}")
  print(f"Tags:             {account.tags}")
  print(f"public access True or False:             {account.allow_blob_public_access}")
  print("=" * 60)