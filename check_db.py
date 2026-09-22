import sqlite3
import os

db_candidates = ['users.db', 'instance/users.db', 'database.db', 'qa.db']
for p in db_candidates:
    if os.path.exists(p):
        print(f'Found: {p}')
        with sqlite3.connect(p) as conn:
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cur.fetchall()]
            print(f'  Tables: {tables}')
            for t in tables:
                try:
                    cur.execute(f'SELECT * FROM "{t}"')
                    rows = cur.fetchall()
                    print(f'  {t}: {rows}')
                except Exception as e:
                    print(f'  {t}: {e}')
    else:
        print(f'Not found: {p}')

