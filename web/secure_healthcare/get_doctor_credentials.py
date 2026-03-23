import sqlite3
import json

conn = sqlite3.connect('healthcare.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()
cur.execute("SELECT id, username, password_hash FROM users WHERE role='doctor'")
rows = [dict(r) for r in cur.fetchall()]
print(json.dumps(rows, indent=2))
