# Secure-Coding-Review
This project reviews a Python web application for security vulnerabilities and demonstrates best practices for secure coding.
1️⃣ Vulnerable Code Example
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Insecure database connection
conn = sqlite3.connect('users.db')
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # ❌ SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        return "Login successful!"
    else:
        return "Invalid credentials."

if __name__ == '__main__':
    app.run(debug=True)



2️⃣ Security Issues Identified

❌ SQL Injection:
    User input is directly concatenated into the SQL query, allowing attackers to inject malicious SQL statements.

❌ Insecure Password Storage:
    Passwords are stored in plain text, making them easily retrievable if the database is compromised.

❌ Unvalidated User Input:
    The application does not sanitize or validate input, increasing the risk of XSS and injection attacks.

❌ Debug Mode Enabled:
    The application runs in debug mode, which exposes sensitive information in error messages.


3️⃣ Fixed Secure Code
import sqlite3
import bcrypt
from flask import Flask, request

app = Flask(__name__)

def get_db_connection():
    return sqlite3.connect('users.db')

# Secure password storage with hashing
def create_user(username, password):
    conn = get_db_connection()
    cursor = conn.cursor()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # ✅ Using parameterized queries to prevent SQL Injection
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    stored_password = cursor.fetchone()
    conn.close()
    
    if stored_password and bcrypt.checkpw(password.encode('utf-8'), stored_password[0]):
        return "Login successful!"
    else:
        return "Invalid credentials."

if __name__ == '__main__':
    app.run(debug=False)  # ✅ Debug mode disabled

4️⃣ Security Recommendations

✅ Preventing SQL Injection:
    Use parameterized queries instead of string concatenation.

✅ Secure Password Storage:
    Hash passwords using bcrypt before storing them in the database.
    Do not store plain-text passwords.

✅ Input Validation:
    Sanitize and validate user input before processing.

✅ Disable Debug Mode:
    Avoid exposing sensitive system details in production.
