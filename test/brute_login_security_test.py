import requests
import time
from datetime import datetime
import os

BASE_URL = 'http://127.0.0.1:5000/brute-login'
SESSION_URL = 'http://127.0.0.1:5000/'
results = []
recommendations = []

TESTS = [
    ("Brute Force Attack Test", "Attempt to brute-force the login with common passwords."),
    ("SQL Injection Test", "Attempt SQL injection in the login form and check for bypass or errors."),
    ("Input Validation Test", "Submit overly long username and check for rejection."),
    ("Error Message Consistency Test", "Check if error messages are consistent for invalid username and password."),
    ("Timing Attack Test", "Measure response time for valid vs invalid credentials to detect timing leaks."),
    ("Account Lockout/Rate Limiting Test", "Check if repeated failed logins trigger a lockout or rate limiting."),
    ("Session Fixation Test", "Attempt to login with a fixed session ID to test for session fixation vulnerability.")
]

TEST_FIXES = {
    "Brute Force Attack Test": "Implement account lockout, CAPTCHA, or rate limiting after several failed login attempts.",
    "SQL Injection Test": "Use parameterized queries for all database operations.",
    "Input Validation Test": "Enforce server-side length and character validation for usernames and passwords.",
    "Error Message Consistency Test": "Return generic error messages for failed logins to avoid information leakage.",
    "Timing Attack Test": "Ensure login response times are consistent regardless of credential validity. Use constant-time comparison functions.",
    "Account Lockout/Rate Limiting Test": "Add rate limiting and account lockout mechanisms to prevent brute force attacks.",
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

# 1. Brute Force Attack Test
success = False
for pwd in ['wrongpass', '123456', 'secret', 'admin']:
    payload = {'username': 'admin', 'password': pwd}
    resp = requests.post(BASE_URL, data=payload)
    if "Welcome" in resp.text and pwd == 'secret':
        success = True
add_result(TESTS[0][0], resp.status_code, 'Brute force succeeded only with correct password.' if success else 'Brute force succeeded with wrong password!', success, TESTS[0][1])

# 2. SQL Injection Test
payload = {'username': "admin' OR '1'='1", 'password': 'anything'}
resp = requests.post(BASE_URL, data=payload)
sqli_success = 'Welcome' not in resp.text
add_result(TESTS[1][0], resp.status_code, 'SQL injection did not bypass login.' if sqli_success else 'SQL injection succeeded or error shown!', sqli_success, TESTS[1][1])

# 3. Input Validation Test
long_username = 'a' * 100
payload = {'username': long_username, 'password': 'test'}
resp = requests.post(BASE_URL, data=payload)
input_valid = 'Invalid' in resp.text or resp.status_code == 400
add_result(TESTS[2][0], resp.status_code, 'Long username rejected.' if input_valid else 'Long username accepted!', input_valid, TESTS[2][1])

# 4. Error Message Consistency Test
resp1 = requests.post(BASE_URL, data={'username': 'admin', 'password': 'wrongpass'})
resp2 = requests.post(BASE_URL, data={'username': 'notarealuser', 'password': 'wrongpass'})
err_consistent = resp1.text == resp2.text
add_result(TESTS[3][0], resp1.status_code, 'Error messages are consistent.' if err_consistent else 'Error messages differ!', err_consistent, TESTS[3][1])

# 5. Timing Attack Test
def measure_time(username, password):
    start = time.time()
    requests.post(BASE_URL, data={'username': username, 'password': password})
    return time.time() - start
valid_time = measure_time('admin', 'secret')
invalid_time = measure_time('admin', 'wrongpass')
timing_success = abs(valid_time - invalid_time) < 0.05
add_result(TESTS[4][0], 'N/A', f'Valid login time: {valid_time:.4f}s, Invalid login time: {invalid_time:.4f}s', timing_success, TESTS[4][1])

# 6. Account Lockout/Rate Limiting Test
lockout_triggered = False
for i in range(7):
    payload = {'username': 'admin', 'password': 'wrongpass'}
    resp = requests.post(BASE_URL, data=payload)
    if 'Too many login attempts' in resp.text:
        lockout_triggered = True
        break
    time.sleep(0.5)
add_result(TESTS[5][0], resp.status_code, 'Lockout triggered.' if lockout_triggered else 'No lockout detected after 7 attempts.', lockout_triggered, TESTS[5][1])

# 7. Session Fixation Test
s = requests.Session()
s.get(SESSION_URL)
s.cookies.set('session', 'fixedsessionid')
resp = s.post(BASE_URL, data={'username': 'admin', 'password': 'secret'})
session_fix = 'Welcome' not in resp.text
add_result(TESTS[6][0], resp.status_code, 'Session fixation not possible.' if session_fix else 'Login succeeded with fixed session ID.', session_fix, TESTS[6][1])

# Save report with timestamp
report_dir = 'test reports'
os.makedirs(report_dir, exist_ok=True)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
report_filename = f'brute_login_security_report_{timestamp}.html'
report_path = os.path.join(report_dir, report_filename)

# Write results to HTML file
html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Brute Login Security Test Report</title>
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
        <h1>Brute Login Security Test Report</h1>
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