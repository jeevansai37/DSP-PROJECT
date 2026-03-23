import sqlite3
import json
conn = sqlite3.connect('c:/Users/jeeva/OneDrive/Desktop/DSP PROJECT/web/secure_healthcare/healthcare.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()
cur.execute("SELECT id, username, role FROM users")
rows = [dict(r) for r in cur.fetchall()]
print(json.dumps(rows, indent=2))
