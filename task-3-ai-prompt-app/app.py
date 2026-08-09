from flask import Flask, render_template, request, Response
import os
import sqlite3
import csv
from datetime import datetime

app = Flask(__name__)

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
    conn.commit()
    conn.close()

init_db()

def get_ai_response(prompt, template):
    api_key = os.getenv('AI_API_KEY')
    if not api_key:
        return f"[MOCK MODE] Template: [{template}] | Processed successfully. Response for: '{prompt}'", "Mock"
    return f"[REAL API MODE] Response for: {prompt}", "Real"

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        prompt = request.form.get('prompt', '').strip()
        template = request.form.get('template', 'General')
        
        if not prompt:
            return render_template('index.html', error="Prompt cannot be empty! Please enter a valid prompt.")
        if len(prompt) > 1000:
            return render_template('index.html', error="Prompt is too long! Please keep it under 1000 characters.")
        
        try:
            response, mode = get_ai_response(prompt, template)
            
            conn = sqlite3.connect('prompt_history.db')
            c = conn.cursor()
            c.execute("INSERT INTO history (timestamp, prompt, template, mode, response, status) VALUES (?,?,?,?,?,?)",
                      (datetime.now(), prompt, template, mode, response, "Success"))
            conn.commit()
            conn.close()
            
            return render_template('index.html', response=response)
        except Exception as e:
            return render_template('index.html', error=f"An error occurred: {strname(e) if 'strname' in globals() else str(e)}")
            
    return render_template('index.html')

@app.route('/history')
def history():
    search = request.args.get('search', '')
    conn = sqlite3.connect('prompt_history.db')
    c = conn.cursor()
    if search:
        c.execute("SELECT * FROM history WHERE prompt LIKE ? ORDER BY timestamp DESC", ('%' + search + '%',))
    else:
        c.execute("SELECT * FROM history ORDER BY timestamp DESC")
    data = c.fetchall()
    conn.close()
    return render_template('history.html', history=data)

@app.route('/export')
def export_csv():
    conn = sqlite3.connect('prompt_history.db')
    c = conn.cursor()
    c.execute("SELECT id, timestamp, prompt, template, mode, response, status FROM history ORDER BY timestamp DESC")
    rows = c.fetchall()
    conn.close()

    def generate():
        yield "ID,Timestamp,Template,Mode,Prompt,Response,Status\n"
        for row in rows:
            yield f'"{row[0]}","{row[1]}","{row[2]}","{row[3]}","{row[4]}","{row[5]}","{row[6]}"\n'

    return Response(generate(), mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=prompt_history.csv"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
