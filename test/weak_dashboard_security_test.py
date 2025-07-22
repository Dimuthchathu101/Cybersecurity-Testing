import requests
import time
from datetime import datetime
import os

LOGIN_URL = 'http://127.0.0.1:5000/weak-login'
DASHBOARD_URL = 'http://127.0.0.1:5000/weak-dashboard'
results = []
recommendations = []

TESTS = [
    ("Session Fixation Test", "Login with a fixed session ID and check if it is accepted."),
    ("Predictable Session ID Test", "Check if the session ID is predictable (e.g., username reversed)."),
    ("Authentication Required Test", "Check if /weak-dashboard is accessible without login."),
    ("Privilege Escalation Test", "Try to access another user's dashboard by changing the session ID."),
    ("Input Validation Test", "Submit empty or invalid username and check for rejection."),
    ("Error Message Consistency Test", "Check if error messages are consistent for valid and invalid logins."),
    ("Timing Attack Test", "Measure response time for valid vs invalid login to detect timing leaks."),
    ("Output Leakage Test", "Check if sensitive info (e.g., session ID) is leaked in the output.")
]

TEST_FIXES = {
    "Session Fixation Test": "Regenerate session IDs after login and do not accept user-supplied session IDs. Use secure, random session tokens.",
    "Predictable Session ID Test": "Use cryptographically secure random session IDs.",
    "Authentication Required Test": "Require authentication for dashboard access and redirect unauthenticated users to login.",
    "Privilege Escalation Test": "Ensure users can only access their own dashboard. Check session ID against logged-in user.",
    "Input Validation Test": "Validate and sanitize all user input. Enforce proper username format.",
    "Error Message Consistency Test": "Return generic error messages for failed logins to avoid information leakage.",
    "Timing Attack Test": "Ensure response times are consistent regardless of input validity.",
    "Output Leakage Test": "Do not leak sensitive info (e.g., session ID) in the output."
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

# 1. Session Fixation Test
s = requests.Session()
s.get(DASHBOARD_URL)
s.cookies.set('session_id', 'fixedsessionid')
resp = s.get(DASHBOARD_URL)
fixation_success = 'fixedsessionid' not in resp.text
add_result(TESTS[0][0], resp.status_code, 'Session fixation not possible.' if fixation_success else 'Dashboard accessible with fixed session ID.', fixation_success, TESTS[0][1])

# 2. Predictable Session ID Test
username = f"weakuser_{int(time.time())}"
resp = requests.post(LOGIN_URL, data={"username": username})
predictable = username[::-1] in resp.text
add_result(TESTS[1][0], resp.status_code, 'Session ID is not predictable.' if not predictable else 'Session ID is predictable!', not predictable, TESTS[1][1])

# 3. Authentication Required Test
resp = requests.get(DASHBOARD_URL)
auth_required = 'session ID' not in resp.text or resp.status_code in (301, 302)
add_result(TESTS[2][0], resp.status_code, 'Dashboard not accessible without login.' if auth_required else 'Dashboard accessible without login!', auth_required, TESTS[2][1])

# 4. Privilege Escalation Test
# Login as user1
user1 = f"user1_{int(time.time())}"
s1 = requests.Session()
s1.post(LOGIN_URL, data={"username": user1})
sid1 = user1[::-1]
# Try to access dashboard as user2 by setting session_id to sid1
user2 = f"user2_{int(time.time())}"
s2 = requests.Session()
s2.post(LOGIN_URL, data={"username": user2})
s2.cookies.set('session_id', sid1)
resp = s2.get(DASHBOARD_URL)
priv_success = sid1 not in resp.text
add_result(TESTS[3][0], resp.status_code, 'Privilege escalation not possible.' if priv_success else 'Dashboard accessible with another user\'s session ID.', priv_success, TESTS[3][1])

# 5. Input Validation Test
resp = requests.post(LOGIN_URL, data={"username": ""})
input_valid = 'Invalid' in resp.text or resp.status_code == 400
add_result(TESTS[4][0], resp.status_code, 'Empty username rejected.' if input_valid else 'Empty username accepted!', input_valid, TESTS[4][1])

# 6. Error Message Consistency Test
resp1 = requests.post(LOGIN_URL, data={"username": ""})
resp2 = requests.post(LOGIN_URL, data={"username": "validuser"})
err_consistent = (resp1.text == resp2.text) or ('Invalid' in resp1.text and 'Invalid' not in resp2.text)
add_result(TESTS[5][0], resp1.status_code, 'Error messages are consistent.' if err_consistent else 'Error messages differ!', err_consistent, TESTS[5][1])

# 7. Timing Attack Test
def measure_time(username):
    start = time.time()
    requests.post(LOGIN_URL, data={"username": username})
    return time.time() - start
valid_time = measure_time('validuser')
invalid_time = measure_time('')
timing_success = abs(valid_time - invalid_time) < 0.05
add_result(TESTS[6][0], 'N/A', f'Valid username time: {valid_time:.4f}s, Invalid username time: {invalid_time:.4f}s', timing_success, TESTS[6][1])

# 8. Output Leakage Test
resp = requests.post(LOGIN_URL, data={"username": "leakuser"})
leakage = 'session ID' in resp.text or 'session_id' in resp.text
add_result(TESTS[7][0], resp.status_code, 'Session ID leaked!' if leakage else 'No session ID leaked.', not leakage, TESTS[7][1])

# Save report with timestamp
report_dir = 'test reports'
os.makedirs(report_dir, exist_ok=True)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
report_filename = f'weak_dashboard_security_report_{timestamp}.html'
report_path = os.path.join(report_dir, report_filename)

# Write results to HTML file
html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Weak Dashboard Security Test Report</title>
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
        <h1>Weak Dashboard Security Test Report</h1>
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