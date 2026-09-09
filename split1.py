str="apple/banana/cherry"

fruits = str.split("/")[1]
print(fruits)
print(str)

raw_id = "/subscriptions/1111-aaaa/resourceGroups/prod-network-rg/providers/Microsoft.Storage/storageAccounts/appdata"

# Full split
pieces = raw_id.split("/")

# Extracting specific parts:
subscription = raw_id.split("/")[2]  # "1111-aaaa"
resource_group = raw_id.split("/")[4]  # "prod-network-rg"
service_type = raw_id.split("/")[7]  # "storageAccounts"
account_name = raw_id.split("/")[8]  # "appdata"

print(f"Resource Group: {resource_group}")
# Output: Resource Group: prod-network-rg
print(pieces)