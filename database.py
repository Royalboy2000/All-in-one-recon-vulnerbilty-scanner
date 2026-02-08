import sqlite3
import os
import json

class DatabaseManager:
    def __init__(self, db_file="redsentry.db"):
        self.db_file = db_file
        self.conn = None
        self.connect()
        self.initialize_tables()

    def connect(self):
        try:
            self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
        except sqlite3.Error as e:
            print(f"Database connection failed: {e}")

    def initialize_tables(self):
        if self.conn:
            cursor = self.conn.cursor()

            # Table for findings
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module TEXT NOT NULL,
                    target TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    data TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            self.conn.commit()

    def save_finding(self, module, target, finding_type, data):
        if self.conn:
            try:
                cursor = self.conn.cursor()
                # Convert list or dict to JSON string if necessary
                if isinstance(data, (dict, list)):
                    data = json.dumps(data)

                cursor.execute('''
                    INSERT INTO findings (module, target, finding_type, data)
                    VALUES (?, ?, ?, ?)
                ''', (module, target, finding_type, str(data)))
                self.conn.commit()
                return True
            except sqlite3.Error as e:
                print(f"Error saving finding: {e}")
                return False
        return False

    def get_findings(self, target=None):
        if self.conn:
            cursor = self.conn.cursor()
            if target:
                cursor.execute('SELECT * FROM findings WHERE target = ?', (target,))
            else:
                cursor.execute('SELECT * FROM findings')
            return cursor.fetchall()
        return []

    def close(self):
        if self.conn:
            self.conn.close()
