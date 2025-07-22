import requests
import time
from datetime import datetime
import os

BASE_URL = 'http://127.0.0.1:5000/login'
SESSION_URL = 'http://127.0.0.1:5000/'

results = []
recommendations = []

TEST_DESCRIPTIONS = [
    ("SQL Injection Test", "Attempts to bypass authentication using a classic SQL injection payload."),
    ("Brute Force Test", "Attempts to brute-force the login by trying several common passwords."),
    ("Input Validation Test", "Checks if the login form properly rejects overly long usernames."),
    ("Account Lockout/Rate Limiting Test", "Checks if repeated failed logins trigger a lockout or rate limiting."),
    ("Timing Attack Test", "Measures response time for valid vs invalid credentials to detect timing leaks."),
    ("Error Message Consistency Test", "Checks if error messages are consistent for invalid username and password."),
    ("CSRF Protection Test", "Checks if the login form includes a CSRF token field."),
    ("Session Fixation Test", "Attempts to login with a fixed session ID to test for session fixation vulnerability.")
]

TEST_FIXES = {
    "SQL Injection Test": "Use parameterized queries or ORM methods instead of string formatting for SQL statements.",
    "Brute Force Test": "Implement account lockout, CAPTCHA, or rate limiting after several failed login attempts.",
    "Input Validation Test": "Validate and sanitize all user input. Enforce reasonable length and character restrictions.",
    "Account Lockout/Rate Limiting Test": "Add rate limiting and account lockout mechanisms to prevent brute force attacks.",
    "Timing Attack Test": "Ensure login response times are consistent regardless of credential validity. Use constant-time comparison functions.",
    "Error Message Consistency Test": "Return generic error messages for failed logins to avoid information leakage.",
    "CSRF Protection Test": "Implement CSRF protection using tokens in all forms that modify state.",
    "Session Fixation Test": "Regenerate session IDs after login and do not accept user-supplied session IDs. Use secure, random session tokens."
}

def add_result(title, status, details, success, description):
    color = '#e6ffed' if success else '#ffeaea'
    border = '2px solid #28a745' if success else '2px solid #dc3545'
    icon = '✅' if success else '❌'
    results.append(f'''
    <div class="test-card" style="background:{color};border:{border};">
        <div class="test-header">
            <span class="test-icon">{icon}</span>
            <span class="test-title">{title}</span>
        </div>
        <div class="test-desc">{description}</div>
        <div class="test-status"><b>Status:</b> {status}</div>
        <div class="test-details"><pre>{details}</pre></div>
    </div>
    ''')
    if not success:
        fix = TEST_FIXES.get(title, "No fix suggestion available.")
        recommendations.append(f'<li><b>{title}:</b> {description}<br><span style="color:#1a73e8"><b>How to fix:</b> {fix}</span></li>')

# Test 1: SQL Injection attempt
payload = {'username': "admin' OR '1'='1", 'password': 'anything'}
resp = requests.post(BASE_URL, data=payload)
sqli_success = 'Welcome' not in resp.text
add_result('SQL Injection Test', resp.status_code, resp.text[:200], sqli_success, TEST_DESCRIPTIONS[0][1])

# Test 2: Brute force (try several passwords)
brute_success = False
brute_details = ''
for pwd in ['wrongpass', '123456', 'secret', 'admin']:
    payload = {'username': 'admin', 'password': pwd}
    resp = requests.post(BASE_URL, data=payload)
    brute_details += f'Trying password: {pwd} | Status: {resp.status_code} | Found: {"Welcome" in resp.text}\n'
    if "Welcome" in resp.text and pwd != 'secret':
        brute_success = False
        break
    if "Welcome" in resp.text and pwd == 'secret':
        brute_success = True
add_result('Brute Force Test', 'Multiple', brute_details, brute_success, TEST_DESCRIPTIONS[1][1])

# Test 3: Input validation (long username)
long_username = 'a' * 100
payload = {'username': long_username, 'password': 'test'}
resp = requests.post(BASE_URL, data=payload)
input_valid = 'Invalid' in resp.text
add_result('Input Validation Test', resp.status_code, resp.text[:200], input_valid, TEST_DESCRIPTIONS[2][1])

# Test 4: Account lockout/rate limiting
lockout_triggered = False
lockout_details = ''
for i in range(7):
    payload = {'username': 'admin', 'password': 'wrongpass'}
    resp = requests.post(BASE_URL, data=payload)
    lockout_details += f'Attempt {i+1}: {resp.status_code} | {resp.text[:100]}\n'
    if 'Too many login attempts' in resp.text:
        lockout_triggered = True
        break
    time.sleep(0.5)
add_result('Account Lockout/Rate Limiting Test', 'Multiple', lockout_details, lockout_triggered, TEST_DESCRIPTIONS[3][1])

# Test 5: Timing attack (measure response time for valid vs invalid password)
def measure_time(username, password):
    start = time.time()
    requests.post(BASE_URL, data={'username': username, 'password': password})
    return time.time() - start
valid_time = measure_time('admin', 'secret')
invalid_time = measure_time('admin', 'wrongpass')
timing_success = abs(valid_time - invalid_time) < 0.05
timing_details = f'Valid login time: {valid_time:.4f}s\nInvalid login time: {invalid_time:.4f}s'
add_result('Timing Attack Test', 'N/A', timing_details, timing_success, TEST_DESCRIPTIONS[4][1])

# Test 6: Error message consistency
resp1 = requests.post(BASE_URL, data={'username': 'admin', 'password': 'wrongpass'})
resp2 = requests.post(BASE_URL, data={'username': 'notarealuser', 'password': 'wrongpass'})
err_consistent = resp1.text == resp2.text
err_details = 'Consistent' if err_consistent else 'Inconsistent error messages!'
add_result('Error Message Consistency Test', 'N/A', err_details, err_consistent, TEST_DESCRIPTIONS[5][1])

# Test 7: CSRF protection (check for CSRF token in login form)
resp = requests.get(BASE_URL)
csrf_found = 'csrf' in resp.text.lower()
csrf_details = 'CSRF token found.' if csrf_found else 'No CSRF token found.'
add_result('CSRF Protection Test', 'N/A', csrf_details, csrf_found, TEST_DESCRIPTIONS[6][1])

# Test 8: Session fixation (reuse session cookie)
s = requests.Session()
s.get(SESSION_URL)
s.cookies.set('session', 'fixedsessionid')
resp = s.post(BASE_URL, data={'username': 'admin', 'password': 'secret'})
session_fix = 'Welcome' not in resp.text
session_details = 'Session fixation not possible.' if session_fix else 'Login succeeded with fixed session ID.'
add_result('Session Fixation Test', 'N/A', session_details, session_fix, TEST_DESCRIPTIONS[7][1])

# Save report with timestamp
report_dir = 'test reports'
os.makedirs(report_dir, exist_ok=True)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
report_filename = f'login_security_report_{timestamp}.html'
report_path = os.path.join(report_dir, report_filename)

# Write results to HTML file
html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Login Security Test Report</title>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 0; }}
        .container {{ max-width: 950px; margin: 40px auto; background: #fff; padding: 30px; border-radius: 12px; box-shadow: 0 4px 16px #bbb; }}
        h1 {{ text-align: center; color: #222; letter-spacing: 1px; }}
        .legend {{ margin: 20px 0; text-align: center; }}
        .legend span {{ display: inline-block; width: 20px; height: 20px; border-radius: 3px; margin-right: 8px; }}
        .test-card {{ margin: 24px 0; padding: 18px 20px; border-radius: 10px; box-shadow: 0 2px 8px #e0e0e0; transition: box-shadow 0.2s; }}
        .test-card:hover {{ box-shadow: 0 4px 16px #b0b0b0; }}
        .test-header {{ display: flex; align-items: center; font-size: 1.2em; margin-bottom: 6px; }}
        .test-icon {{ font-size: 1.5em; margin-right: 12px; }}
        .test-title {{ font-weight: bold; color: #222; }}
        .test-desc {{ color: #555; margin-bottom: 8px; font-size: 0.98em; }}
        .test-status {{ margin-bottom: 6px; }}
        .test-details pre {{ background: #f8f9fa; padding: 10px; border-radius: 6px; font-size: 0.97em; overflow-x: auto; }}
        h2 {{ color: #1a73e8; margin-top: 40px; }}
        ul {{ margin-left: 20px; }}
        @media (max-width: 600px) {{
            .container {{ padding: 10px; }}
            .test-card {{ padding: 10px 6px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Login Security Test Report</h1>
        <p><b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <div class="legend">
            <b>Legend:</b>
            <span style="background:#e6ffed; border:2px solid #28a745"></span> Pass
            <span style="background:#ffeaea; border:2px solid #dc3545"></span> Fail
        </div>
        {''.join(results)}
        <h2>Recommendations</h2>
        <ul>
            {''.join(recommendations) if recommendations else '<li>All tests passed. No critical issues detected.</li>'}
        </ul>
    </div>
</body>
</html>
"""

with open(report_path, 'w') as f:
    f.write(html)

print(f"\nReport saved to {report_path}") 