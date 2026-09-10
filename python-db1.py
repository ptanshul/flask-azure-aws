import pyodbc

# Connection details
server = "myserver900demo.database.windows.net"
database = "skilldb"
username = "myadmin"
password = "Pass@12345678"  # Ensure this matches the password set for myserver900demo
driver = "{ODBC Driver 18 for SQL Server}"

# Connection string with TLS/Encryption parameters required by Azure
conn_str = (
    f"DRIVER={driver};"
    f"SERVER={server};"
    f"DATABASE={database};"
    f"UID={username};"
    f"PWD={password};"
    "Encrypt=yes;"
    "TrustServerCertificate=yes;"
    "Connection Timeout=30;"
)

try:
    print(f"Connecting to {server} using {driver}...")
    with pyodbc.connect(conn_str) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT name, city, skill FROM employees")
            rows = cursor.fetchall()
            
            print("\nFetched Records:")
            print("-" * 45)
            for row in rows:
                print(f"Name: {row.name:<15} | City: {row.city:<12} | Skill: {row.skill}")

except pyodbc.Error as e:
    print(f"\nDatabase Error:\n{e}")