import sqlite3
import os
from flask import g

DB_NAME = "healthcare.db"

def get_db():
    """Return the SQLite database connection using Flask's g object."""
    if 'db' not in g:
        # Determine the absolute path to the database file
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), DB_NAME)
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row  # This allows accessing columns by name
    return g.db

def close_db(e=None):
    """Close the database connection at the end of a request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()
