import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from dotenv import load_dotenv

load_dotenv()

client = StorageManagementClient(
    DefaultAzureCredential(), os.getenv("AZURE_SUBSCRIPTION_ID")
)

for account in client.storage_accounts.list():
  rg = account.id.split("/")[4]
  print(account.id)
  print(f"Account: {account.name} | RG: {rg}")