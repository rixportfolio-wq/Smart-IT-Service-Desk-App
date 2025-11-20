import sqlite3

conn = sqlite3.connect("database.db")
cur = conn.cursor()
cur.execute("ALTER TABLE tickets ADD COLUMN created_by TEXT;")
conn.commit()
conn.close()

print("Column created_by added!")
