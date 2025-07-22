from flask import Flask, render_template, request, redirect, url_for, send_from_directory, make_response, session
import sqlite3
import os
import re
import time
import hashlib
import logging
import signal

app = Flask(__name__)
app.secret_key = 'change_this_secret_key'

# Vulnerable database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)''')
    c.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (1, 'admin', 'secret', 'admin@example.com', 'admin')")
    c.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (2, 'alice', 'alicepass', 'alice@example.com', 'user')")
    c.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (3, 'bob', 'bobpass', 'bob@example.com', 'user')")
    # Add comments table for stored XSS
    c.execute('''CREATE TABLE IF NOT EXISTS comments
                 (id INTEGER PRIMARY KEY, content TEXT, username TEXT, timestamp TEXT)''')
    conn.commit()
    conn.close()

# Home page with XSS vulnerability
# @app.route('/')
# def home():
#     search_query = request.args.get('search', '')
#     return render_template('index.html', search_query=search_query)

# Add a simple in-memory rate limiter
login_attempts = {}

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    success = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        role = 'user'
        if not re.match(r'^[\w-]{3,30}$', username):
            error = 'Username must be 3-30 characters, letters/numbers/underscore/hyphen.'
        elif not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            error = 'Invalid email address.'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters.'
        else:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('SELECT id FROM users WHERE username=? OR email=?', (username, email))
            if c.fetchone():
                error = 'Username or email already exists.'
            else:
                hashed = hashlib.sha256(password.encode()).hexdigest()
                c.execute('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)', (username, hashed, email, role))
                conn.commit()
                conn.close()
                success = 'Registration successful. You can now log in.'
    return render_template('register.html', error=error, success=success)

# Profile view/edit
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, username, email, role FROM users WHERE id=?', (session['user_id'],))
    user = c.fetchone()
    error = None
    success = None
    if request.method == 'POST':
        new_email = request.form['email']
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', new_email):
            error = 'Invalid email address.'
        else:
            c.execute('UPDATE users SET email=? WHERE id=?', (new_email, session['user_id']))
            conn.commit()
            success = 'Profile updated.'
            user = (user[0], user[1], new_email, user[3])
    conn.close()
    return render_template('profile.html', user=user, error=error, success=success)

# Enhanced users list with roles and admin delete
@app.route('/users')
def users():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, username, email, role FROM users')
    user_list = c.fetchall()
    conn.close()
    is_admin = session.get('role') == 'admin'
    return render_template('users.html', users=user_list, is_admin=is_admin)

@app.route('/delete-user', methods=['POST'])
def delete_user():
    if session.get('role') != 'admin':
        return 'Unauthorized', 403
    user_id = request.form['user_id']
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE id=?', (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('users'))

# Update login to use hashed passwords and set session
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password or len(username) > 50 or len(password) > 50:
            error = "Invalid input."
            return render_template('login.html', error=error)
        ip = request.remote_addr
        now = time.time()
        attempts = login_attempts.get(ip, [])
        attempts = [t for t in attempts if now - t < 60]
        if len(attempts) >= 5:
            error = "Too many login attempts. Please try again later."
            return render_template('login.html', error=error)
        attempts.append(now)
        login_attempts[ip] = attempts
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        hashed = hashlib.sha256(password.encode()).hexdigest()
        c.execute("SELECT id, username, role FROM users WHERE username=? AND password=?", (username, hashed))
        user = c.fetchone()
        conn.close()
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[2]
            return f"Welcome {user[1]}!"
        else:
            error = "Invalid credentials"
    return render_template('login.html', error=error)

@app.route('/comments', methods=['GET', 'POST'])
def comments():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    error = None
    success = None
    # Ensure new columns exist
    try:
        c.execute("ALTER TABLE comments ADD COLUMN parent_id INTEGER")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE comments ADD COLUMN deleted INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    # Ensure votes table exists
    c.execute('''CREATE TABLE IF NOT EXISTS comment_votes (
        id INTEGER PRIMARY KEY, comment_id INTEGER, username TEXT, vote INTEGER)''')
    if request.method == 'POST':
        action = request.form.get('action', 'add')
        if action == 'add':
            comment = request.form['comment']
            username = request.form.get('username', 'Anonymous')
            parent_id = request.form.get('parent_id')
            parent_id = int(parent_id) if parent_id and parent_id.isdigit() else None
            if not comment or len(comment) > 500:
                error = 'Comment must be 1-500 characters.'
            else:
                from datetime import datetime, timedelta
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                # Anti-spam: block duplicate comment from same user within 1 minute
                c.execute("SELECT timestamp FROM comments WHERE username=? AND content=? ORDER BY id DESC LIMIT 1", (username, comment))
                last = c.fetchone()
                if last:
                    last_time = datetime.strptime(last[0], '%Y-%m-%d %H:%M:%S')
                    if (datetime.now() - last_time).total_seconds() < 60:
                        error = 'You cannot post the same comment again so soon.'
                if not error:
                    c.execute("INSERT INTO comments (content, username, timestamp, parent_id, deleted) VALUES (?, ?, ?, ?, 0)", (comment, username, timestamp, parent_id))
                    conn.commit()
                    success = 'Comment posted.'
        elif action == 'delete':
            comment_id = request.form.get('comment_id')
            username = request.form.get('username', 'Anonymous')
            c.execute("SELECT username FROM comments WHERE id=?", (comment_id,))
            row = c.fetchone()
            if row and (row[0] == username or username.lower() == 'admin'):
                c.execute("UPDATE comments SET deleted=1 WHERE id=?", (comment_id,))
                conn.commit()
                success = 'Comment deleted.'
            else:
                error = 'You can only delete your own comments.'
        elif action in ['upvote', 'downvote']:
            comment_id = request.form.get('comment_id')
            username = request.form.get('username', 'Anonymous')
            vote_val = 1 if action == 'upvote' else -1
            # Prevent multiple votes per user per comment
            c.execute("SELECT id FROM comment_votes WHERE comment_id=? AND username=?", (comment_id, username))
            if c.fetchone():
                error = 'You have already voted on this comment.'
            else:
                c.execute("INSERT INTO comment_votes (comment_id, username, vote) VALUES (?, ?, ?)", (comment_id, username, vote_val))
                conn.commit()
                success = 'Vote recorded.'
    # Sorting
    sort = request.args.get('sort', 'newest')
    c.execute("SELECT id, content, username, timestamp, parent_id FROM comments WHERE deleted=0")
    all_comments = c.fetchall()
    # Get vote counts for each comment
    vote_counts = {}
    for row in all_comments:
        c.execute("SELECT SUM(vote) FROM comment_votes WHERE comment_id=?", (row[0],))
        count = c.fetchone()[0] or 0
        vote_counts[row[0]] = count
    # Sort comments
    if sort == 'upvoted':
        all_comments = sorted(all_comments, key=lambda c: vote_counts.get(c[0], 0), reverse=True)
    else:
        all_comments = sorted(all_comments, key=lambda c: c[0], reverse=True)
    conn.close()
    # Build threaded structure
    def build_thread(comments, parent=None):
        thread = []
        for c in comments:
            if c[4] == parent:
                replies = build_thread(comments, c[0])
                thread.append({
                    'id': c[0], 'content': c[1], 'username': c[2], 'timestamp': c[3], 'parent_id': c[4], 'replies': replies, 'votes': vote_counts.get(c[0], 0)
                })
        return thread
    comment_thread = build_thread(all_comments)
    return render_template('comments.html', comments=comment_thread, error=error, success=success, sort=sort)

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

# Setup error logging
logging.basicConfig(filename='error_demo.log', level=logging.ERROR, format='%(asctime)s %(levelname)s %(message)s')

class TimeoutException(Exception): pass

def handler(signum, frame):
    raise TimeoutException('Infinite loop timed out!')

@app.route('/crash', methods=['GET', 'POST'])
def crash():
    error_type = request.args.get('type')
    if request.method == 'POST':
        error_type = request.form.get('type')
    try:
        if error_type == 'zero':
            return 1 / 0
        elif error_type == 'key':
            d = {}
            return d['missing']
        elif error_type == 'type':
            return len(5)
        elif error_type == 'custom':
            class CustomError(Exception): pass
            raise CustomError('This is a custom exception!')
        elif error_type == '404':
            return "Not Found", 404
        elif error_type == '403':
            return "Forbidden", 403
        elif error_type == '500':
            return "Internal Server Error", 500
        elif error_type == 'slow':
            import time
            time.sleep(5)
            return "Simulated slow response (5 seconds)"
        elif error_type == 'memory':
            a = []
            for _ in range(10**8):
                a.append('x' * 1000)
            return "Should have triggered MemoryError"
        elif error_type == 'os':
            open('/file/does/not/exist.txt')
        elif error_type == 'loop':
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(3)  # 3 second timeout
            try:
                while True:
                    pass
            except TimeoutException as te:
                logging.error(f"Crash demo timeout: {repr(te)}", exc_info=True)
                return "Infinite loop timed out after 3 seconds"
            finally:
                signal.alarm(0)
    except Exception as e:
        logging.error(f"Crash demo error: {repr(e)}", exc_info=True)
        raise
    # Show a form to select error type
    return render_template('crash.html')

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