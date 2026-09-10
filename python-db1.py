import pyodbc

# List available drivers on this machine
drivers = [d for d in pyodbc.drivers() if "SQL Server" in d]

if not drivers:
    raise RuntimeError(
        "No SQL Server ODBC driver found. "
        "Please download and install ODBC Driver 18 from: "
        "https://aka.ms/downloadmsodbcsql"
    )

# Use the latest available driver found (e.g., Driver 18 or 17)
selected_driver = drivers[0]
print(f"Using driver: {selected_driver}")

server = "myserver900demo.database.windows.net"  # Set your actual server name
database = "skilldb"
username = "myadmin"
password = "Pass@123"                  # Set your actual password

conn_str = (
    f"DRIVER={{{selected_driver}}};"
    f"SERVER={server};"
    f"DATABASE={database};"
    f"UID={username};"
    f"PWD={password};"
    "Encrypt=yes;"
    "TrustServerCertificate=yes;"           # Helps bypass local SSL handshake issues
    "Connection Timeout=30;"
)

try:
    print("Connecting to Azure SQL...")
    with pyodbc.connect(conn_str) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT name, city, skill FROM employees")
            rows = cursor.fetchall()
            print("\nRecords:")
            for row in rows:
                print(f"Name: {row.name} | City: {row.city} | Skill: {row.skill}")

except pyodbc.Error as e:
    print(f"Error: {e}")