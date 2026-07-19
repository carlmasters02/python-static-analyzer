"""Labeled benchmark cases — SQL injection.

Markers (hash-at-VULN should flag / hash-at-SAFE should not flag).
Keep each .execute(...) on a single line so line numbers match.
"""


# ---- Should be caught (true vulnerabilities) ------------------------------

def concat(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + username + "'")  #@ VULN


def fstring(conn):
    term = input()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM products WHERE title LIKE '%{term}%'")  #@ VULN


def dot_format(conn, uid):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = {}".format(uid))  #@ VULN


def percent(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT * FROM t WHERE n = '%s'" % name)  #@ VULN


# ---- Should NOT be caught (safe lookalikes) -------------------------------

def parameterized_qmark(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (username,))  #@ SAFE


def parameterized_named(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT * FROM t WHERE n = %(n)s", {"n": name})  #@ SAFE


def constant_query(conn):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")  #@ SAFE


def executemany_parameterized(conn, rows):
    cur = conn.cursor()
    cur.executemany("INSERT INTO t VALUES (?, ?)", rows)  #@ SAFE
