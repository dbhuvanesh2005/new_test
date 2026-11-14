import os
import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)

# Initialize a temporary in-memory database for testing
def init_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)")
    cursor.execute("INSERT INTO users (username, role) VALUES ('alice', 'user'), ('admin', 'administrator')")
    conn.commit()
    return conn

db_conn = init_db()

@app.route("/")
def index():
    return """
    <h2>Security Scanner Test Endpoints</h2>
    <ul>
        <li><b>SQL Injection:</b> /user?username=alice</li>
        <li><b>Reflected XSS:</b> /greet?name=Guest</li>
        <li><b>Command Injection:</b> /ping?host=127.0.0.1</li>
    </ul>
    """

# 1. VULNERABILITY: SQL Injection (SQLi)
# Flaw: User input is concatenated directly into the SQL query string.
@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    cursor = db_conn.cursor()
    
    # INSECURE: String formatting allows query manipulation
    query = f"SELECT id, username, role FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchall()
    return {"result": result}

# 2. VULNERABILITY: Reflected Cross-Site Scripting (XSS)
# Flaw: User input is returned directly in the HTML response without escaping.
@app.route("/greet")
def greet():
    name = request.args.get("name", "Guest")
    
    # INSECURE: Raw string interpolation into HTML
    return f"<h1>Hello, {name}!</h1>"

# 3. VULNERABILITY: OS Command Injection
# Flaw: User input is passed directly to a system shell.
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    
    # INSECURE: shell=True with unsanitized input allows command chaining
    output = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return f"<pre>{output}</pre>"

if __name__ == "__main__":
    # Debug mode should also be disabled in production
    app.run(host="127.0.0.1", port=5000, debug=False)
