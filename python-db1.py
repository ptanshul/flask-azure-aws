#python dbimport pyodbc

# Use your exact server name here
server = "myserver900demo.database.windows.net"
database = "skilldb"
username = "myadmin"
password = "Pass@123"
driver = "{ODBC Driver 18 for SQL Server}"

conn_str = (
    f"DRIVER={driver};"
    f"SERVER={server};"
    f"DATABASE={database};"
    f"UID={username};"
    f"PWD={password};"
    "Encrypt=yes;"
    "TrustServerCertificate=no;"
    "Connection Timeout=30;"
)

try:
    with pyodbc.connect(conn_str) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT name, city, skill FROM employees")
            for row in cursor.fetchall():
                print(f"{row.name} | {row.city} | {row.skill}")
except pyodbc.Error as e:
    print(f"Error: {e}")