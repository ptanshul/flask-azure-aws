import os
import pymssql
from flask import Flask, render_template_string, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

DB_SERVER   = os.getenv("DB_SERVER")
DB_DATABASE = os.getenv("DB_DATABASE")
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")


# ── db helper ─────────────────────────────────────────────────────────────────

def get_employees():
    conn = pymssql.connect(
        server=DB_SERVER,
        user=DB_USERNAME,
        password=DB_PASSWORD,
        database=DB_DATABASE,
    )
    try:
        cursor = conn.cursor(as_dict=True)
        cursor.execute("SELECT name, city, skill FROM employees")
        return cursor.fetchall()
    finally:
        conn.close()


# ── HTML template ─────────────────────────────────────────────────────────────

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Employee Directory</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: Segoe UI, Arial, sans-serif; background: #f0f2f5; color: #1a1a1a; }

    header {
      background: #0078d4; color: #fff;
      padding: 18px 32px;
      display: flex; justify-content: space-between; align-items: center;
    }
    header h1 { font-size: 1.35rem; font-weight: 600; }
    header .sub { font-size: 0.8rem; opacity: 0.8; margin-top: 3px; }
    .refresh-btn {
      color: #fff; text-decoration: none; font-size: 0.8rem;
      border: 1px solid rgba(255,255,255,.5); padding: 5px 14px; border-radius: 4px;
    }
    .refresh-btn:hover { background: rgba(255,255,255,.15); }

    .stats { display: flex; gap: 14px; padding: 24px 32px 0; flex-wrap: wrap; }
    .stat {
      background: #fff; border-radius: 6px; padding: 14px 24px;
      min-width: 150px; box-shadow: 0 1px 3px rgba(0,0,0,.1);
    }
    .stat .lbl { font-size: 0.72rem; color: #666; text-transform: uppercase; letter-spacing: .5px; }
    .stat .val { font-size: 2rem; font-weight: 700; margin-top: 4px; color: #0078d4; }

    .section { padding: 24px 32px; }
    .section h2 { font-size: 1rem; font-weight: 600; color: #333; margin-bottom: 14px; }

    table {
      width: 100%; border-collapse: collapse; background: #fff;
      border-radius: 6px; overflow: hidden;
      box-shadow: 0 1px 3px rgba(0,0,0,.1); font-size: 0.875rem;
    }
    th {
      background: #f7f7f7; text-align: left; padding: 11px 16px;
      font-weight: 600; border-bottom: 2px solid #e1e1e1; color: #444;
      text-transform: uppercase; font-size: 0.75rem; letter-spacing: .4px;
    }
    td { padding: 11px 16px; border-bottom: 1px solid #f0f0f0; vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #f5faff; }

    .skill-badge {
      display: inline-block; padding: 2px 10px; border-radius: 10px;
      font-size: 0.75rem; font-weight: 600;
      background: #ddeeff; color: #0055aa;
    }

    .empty { text-align: center; padding: 40px; color: #aaa; }

    footer {
      padding: 14px 32px; font-size: 0.78rem; color: #888;
      border-top: 1px solid #e1e1e1; margin-top: 8px;
    }
    footer a { color: #0078d4; text-decoration: none; margin-right: 14px; }
    footer a:hover { text-decoration: underline; }
  </style>
</head>
<body>

<header>
  <div>
    <h1>&#128100; Employee Directory</h1>
    <div class="sub">{{ db_server }} &nbsp;/&nbsp; {{ db_name }}</div>
  </div>
  <a class="refresh-btn" href="/">&#8635; Refresh</a>
</header>

<div class="stats">
  <div class="stat">
    <div class="lbl">Total Employees</div>
    <div class="val">{{ employees | length }}</div>
  </div>
  <div class="stat">
    <div class="lbl">Unique Cities</div>
    <div class="val">{{ employees | map(attribute='city') | unique | list | length }}</div>
  </div>
  <div class="stat">
    <div class="lbl">Unique Skills</div>
    <div class="val">{{ employees | map(attribute='skill') | unique | list | length }}</div>
  </div>
</div>

<div class="section">
  <h2>All Employees</h2>
  {% if employees %}
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>Name</th>
        <th>City</th>
        <th>Skill</th>
      </tr>
    </thead>
    <tbody>
      {% for emp in employees %}
      <tr>
        <td style="color:#aaa;font-size:0.8rem;">{{ loop.index }}</td>
        <td><strong>{{ emp.name }}</strong></td>
        <td>{{ emp.city }}</td>
        <td><span class="skill-badge">{{ emp.skill }}</span></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">No employee records found.</div>
  {% endif %}
</div>

<footer>
  <a href="/api/employees">JSON: All Employees</a>
</footer>

</body>
</html>"""


# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    try:
        employees = get_employees()
        return render_template_string(
            TEMPLATE,
            employees=employees,
            db_server=DB_SERVER,
            db_name=DB_DATABASE,
        )
    except Exception as err:
        return f"<pre style='padding:32px;color:red'>Database Error:\n{err}</pre>", 500


@app.route("/api/employees")
def api_employees():
    try:
        employees = get_employees()
        return jsonify({
            "database": DB_DATABASE,
            "total": len(employees),
            "employees": employees,
        })
    except Exception as err:
        return jsonify({"error": str(err)}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002, debug=True)
