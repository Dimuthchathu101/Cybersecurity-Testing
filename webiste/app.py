from flask import Flask, render_template, request, redirect, url_for, send_from_directory, make_response
import sqlite3
import os
import re
import time
from flask import session

app = Flask(__name__)

# Vulnerable database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)''')
    c.execute("INSERT OR IGNORE INTO users (id, username, password, email) VALUES (1, 'admin', 'secret', 'admin@example.com')")
    c.execute("INSERT OR IGNORE INTO users (id, username, password, email) VALUES (2, 'alice', 'alicepass', 'alice@example.com')")
    c.execute("INSERT OR IGNORE INTO users (id, username, password, email) VALUES (3, 'bob', 'bobpass', 'bob@example.com')")
    # Add comments table for stored XSS
    c.execute('''CREATE TABLE IF NOT EXISTS comments
                 (id INTEGER PRIMARY KEY, content TEXT)''')
    conn.commit()
    conn.close()

# Home page with XSS vulnerability
# @app.route('/')
# def home():
#     search_query = request.args.get('search', '')
#     return render_template('index.html', search_query=search_query)

# Add a simple in-memory rate limiter
login_attempts = {}

# Login page with SQL injection vulnerability
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Basic input validation
        if not username or not password or len(username) > 50 or len(password) > 50:
            error = "Invalid input."
            return render_template('login.html', error=error)
        # Rate limiting: max 5 attempts per minute per IP
        ip = request.remote_addr
        now = time.time()
        attempts = login_attempts.get(ip, [])
        attempts = [t for t in attempts if now - t < 60]
        if len(attempts) >= 5:
            error = "Too many login attempts. Please try again later."
            return render_template('login.html', error=error)
        attempts.append(now)
        login_attempts[ip] = attempts
        # Use parameterized query to prevent SQL injection
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['user_id'] = user[0]
            return f"Welcome {user[1]}!"
        else:
            error = "Invalid credentials"
    return render_template('login.html', error=error)

@app.route('/comments', methods=['GET', 'POST'])
def comments():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    if request.method == 'POST':
        comment = request.form['comment']
        c.execute("INSERT INTO comments (content) VALUES (?)", (comment,))
        conn.commit()
    c.execute("SELECT content FROM comments")
    all_comments = c.fetchall()
    conn.close()
    return render_template('comments.html', comments=all_comments)

@app.route('/users')
def users():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, username FROM users')
    user_list = c.fetchall()
    conn.close()
    return render_template('users.html', users=user_list)

@app.route('/profile')
def profile():
    user_id = request.args.get('id')
    user = None
    if user_id:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT id, username, email FROM users WHERE id=?', (user_id,))
        user = c.fetchone()
        conn.close()
    return render_template('profile.html', user=user, user_id=user_id)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    message = None
    if request.method == 'POST':
        if 'file' not in request.files:
            message = 'No file part'
        else:
            file = request.files['file']
            if file.filename == '':
                message = 'No selected file'
            else:
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                file.save(filepath)
                message = f'File {file.filename} uploaded!'
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('upload.html', message=message, files=files)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/redirect')
def open_redirect():
    next_url = request.args.get('next')
    if not next_url:
        return 'No next parameter provided', 400
    # If next_url starts with http or //, treat as external
    if re.match(r'^(https?:)?//', next_url):
        return redirect(next_url)
    # Otherwise, treat as internal
    return redirect(url_for('login') if next_url == '/login' else next_url)

@app.route('/redirect-demo')
def redirect_demo():
    return render_template('redirect_demo.html')

@app.route('/search', methods=['GET', 'POST'])
def search():
    results = []
    query = ''
    if request.method == 'POST':
        query = request.form['query']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        # Vulnerable SQL query (not parameterized)
        sql = f"SELECT id, username, email FROM users WHERE username LIKE '%{query}%'"
        try:
            c.execute(sql)
            results = c.fetchall()
        except Exception as e:
            results = [(str(e), '', '')]
        conn.close()
    return render_template('search.html', results=results, query=query)

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    message = None
    if request.method == 'POST':
        user_id = request.form['user_id']
        new_password = request.form['new_password']
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('UPDATE users SET password=? WHERE id=?', (new_password, user_id))
            conn.commit()
            conn.close()
            message = f'Password for user id {user_id} changed!'
        except Exception as e:
            message = f'Error: {e}'
    return render_template('change_password.html', message=message)

@app.route('/crash')
def crash():
    # This will raise a ZeroDivisionError and show the stack trace
    return 1 / 0

@app.route('/weak-login', methods=['GET', 'POST'])
def weak_login():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        # Predictable session ID: just the username reversed
        session_id = username[::-1]
        resp = make_response(redirect(url_for('weak_dashboard', session_id=session_id)))
        resp.set_cookie('session_id', session_id)
        return resp
    return render_template('weak_login.html', message=message)

@app.route('/weak-dashboard')
def weak_dashboard():
    session_id = request.args.get('session_id') or request.cookies.get('session_id')
    return render_template('weak_dashboard.html', session_id=session_id)

@app.route('/ping', methods=['GET', 'POST'])
def ping():
    output = None
    host = ''
    if request.method == 'POST':
        host = request.form['host']
        # Vulnerable to command injection
        cmd = f'ping -c 1 {host}'
        output = os.popen(cmd).read()
    return render_template('ping.html', output=output, host=host)

@app.route('/brute-login', methods=['GET', 'POST'])
def brute_login():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        c.execute(query)
        user = c.fetchone()
        conn.close()
        if user:
            message = f"Welcome {user[1]}! (Brute-force demo)"
        else:
            message = "Invalid credentials (Brute-force demo)"
    return render_template('brute_login.html', message=message)

@app.route('/')
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True) 