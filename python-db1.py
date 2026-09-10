import pymssql

server = "myserver900demo.database.windows.net"
database = "skilldb"
username = "myadmin"
password = "Pass@12345678"  # Your actual password

try:
    print(f"Connecting to {server}...")
    conn = pymssql.connect(
        server=server,
        user=username,
        password=password,
        database=database
    )
    cursor = conn.cursor(as_dict=True)
    cursor.execute("SELECT name, city, skill FROM employees")

    print("\nFetched Records:")
    print("-" * 45)
    for row in cursor.fetchall():
        print(f"Name: {row['name']:<15} | City: {row['city']:<12} | Skill: {row['skill']}")

    conn.close()

except Exception as e:
    print(f"\nDatabase Error:\n{e}")