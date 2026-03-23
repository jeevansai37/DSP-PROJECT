import sqlite3
conn = sqlite3.connect('c:/Users/jeeva/OneDrive/Desktop/DSP PROJECT/web/secure_healthcare/healthcare.db')
conn.row_factory = sqlite3.Row
cur = conn.cursor()
cur.execute("SELECT id, username, role FROM users WHERE role='doctor'")
for row in cur.fetchall():
    print(dict(row))
