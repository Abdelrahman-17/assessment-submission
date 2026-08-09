import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect('prompt_history.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp DATETIME,
                  prompt TEXT,
                  template TEXT,
                  mode TEXT,
                  response TEXT,
                  status TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS counters
                 (template TEXT PRIMARY KEY,
                  count INTEGER DEFAULT 0)''')
    conn.commit()
    conn.close()

def log_prompt(prompt, template, mode, response, status):
    conn = sqlite3.connect('prompt_history.db')
    c = conn.cursor()
    c.execute("INSERT INTO history (timestamp, prompt, template, mode, response, status) VALUES (?,?,?,?,?,?)",
              (datetime.now(), prompt, template, mode, response, status))
    c.execute("INSERT OR IGNORE INTO counters (template, count) VALUES (?, 0)", (template,))
    c.execute("UPDATE counters SET count = count + 1 WHERE template = ?", (template,))
    conn.commit()
    conn.close()
