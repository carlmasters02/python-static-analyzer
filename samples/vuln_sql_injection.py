"""DELIBERATELY VULNERABLE sample — SQL injection.

Do not run against a real database. Labels mark ground truth for testing.
"""

import sqlite3


def get_user_vulnerable(conn, username):
    # VULNERABLE: untrusted 'username' concatenated into the SQL string.
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchall()


def search_vulnerable(conn):
    # VULNERABLE: user input via input() f-stringed into the query.
    term = input("search: ")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE title LIKE '%{term}%'")
    return cursor.fetchall()


def get_user_safe(conn, username):
    # SAFE: parameterized query. The '?' placeholder keeps data and code
    # separate, so 'username' can never change the query's structure.
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cursor.fetchall()


def count_all_safe(conn):
    # SAFE: fully constant query, no user data at all.
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    return cursor.fetchone()
