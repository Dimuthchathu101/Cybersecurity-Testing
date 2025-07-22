import requests
import time
from datetime import datetime
import os

USERS_URL = 'http://127.0.0.1:5000/users'
DELETE_URL = 'http://127.0.0.1:5000/delete-user'
LOGIN_URL = 'http://127.0.0.1:5000/login'
REGISTER_URL = 'http://127.0.0.1:5000/register'
results = []
recommendations = []

TESTS = [
    ("Authentication Required Test", "Check if /users is accessible without authentication."),
    ("Privilege Escalation Test", "Try to delete a user as a non-admin and check for rejection."),
    ("Input Validation Test", "Try to delete a user with an invalid user_id and check for rejection."),
    ("Error Message Consistency Test", "Check if error messages are consistent for valid and invalid delete attempts."),
    ("Timing Attack Test", "Measure response time for valid vs invalid delete attempts to detect timing leaks."),
    ("Output Leakage Test", "Check if sensitive info (e.g., emails, roles) is leaked to non-admins."),
    ("Rate Limiting Test", "Check if repeated delete requests trigger rate limiting or blocking.")
]

TEST_FIXES = {
    "Authentication Required Test": "Require authentication for user list access and redirect unauthenticated users to login.",
    "Privilege Escalation Test": "Only allow admin users to delete other users. Check user role in session.",
    "Input Validation Test": "Validate and sanitize all user input. Reject invalid user IDs.",
    "Error Message Consistency Test": "Return generic error messages for failed delete attempts to avoid information leakage.",
    "Timing Attack Test": "Ensure response times are consistent regardless of input validity.",
    "Output Leakage Test": "Do not leak sensitive user info (emails, roles) to non-admins.",
    "Rate Limiting Test": "Add rate limiting to prevent abuse of the delete endpoint."
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

# Helper: Register and login a test user
session = requests.Session()
username = f"testuser_{int(time.time())}"
password = "TestPass123!"
email = f"{username}@example.com"
# Register
session.post(REGISTER_URL, data={"username": username, "email": email, "password": password, "confirm": password, "role": "user"})
# Login
session.post(LOGIN_URL, data={"username": username, "password": password})

# 1. Authentication Required Test
resp = requests.get(USERS_URL)
auth_required = '/login' in resp.url or resp.status_code in (301, 302)
add_result(TESTS[0][0], resp.status_code, 'Redirected to login.' if auth_required else 'Users accessible without login!', auth_required, TESTS[0][1])

# 2. Privilege Escalation Test
# Try to delete a user as a non-admin
resp = session.post(DELETE_URL, data={"user_id": "1"})
priv_success = resp.status_code == 403 or 'unauthorized' in resp.text.lower()
add_result(TESTS[1][0], resp.status_code, 'Delete as non-admin blocked.' if priv_success else 'Delete as non-admin allowed!', priv_success, TESTS[1][1])

# 3. Input Validation Test
resp = session.post(DELETE_URL, data={"user_id": "notanid"})
input_valid = resp.status_code == 400 or 'invalid' in resp.text.lower() or 'error' in resp.text.lower()
add_result(TESTS[2][0], resp.status_code, 'Invalid user_id rejected.' if input_valid else 'Invalid user_id accepted!', input_valid, TESTS[2][1])

# 4. Error Message Consistency Test
resp1 = session.post(DELETE_URL, data={"user_id": "1"})
resp2 = session.post(DELETE_URL, data={"user_id": "notanid"})
err_consistent = (resp1.text == resp2.text) or ('Invalid' in resp1.text and 'Invalid' not in resp2.text)
add_result(TESTS[3][0], resp1.status_code, 'Error messages are consistent.' if err_consistent else 'Error messages differ!', err_consistent, TESTS[3][1])

# 5. Timing Attack Test
def measure_time(user_id):
    start = time.time()
    session.post(DELETE_URL, data={"user_id": user_id})
    return time.time() - start
valid_time = measure_time("1")
invalid_time = measure_time("notanid")
timing_success = abs(valid_time - invalid_time) < 0.05
add_result(TESTS[4][0], 'N/A', f'Valid user_id time: {valid_time:.4f}s, Invalid user_id time: {invalid_time:.4f}s', timing_success, TESTS[4][1])

# 6. Output Leakage Test
resp = session.get(USERS_URL)
leakage = any(word in resp.text.lower() for word in ['admin', 'user', '@', 'role'])
add_result(TESTS[5][0], resp.status_code, 'Sensitive info leaked!' if leakage else 'No sensitive info leaked.', not leakage, TESTS[5][1])

# 7. Rate Limiting Test
rate_limited = False
for i in range(10):
    resp = session.post(DELETE_URL, data={"user_id": "1"})
    if 'rate limit' in resp.text.lower():
        rate_limited = True
        break
    time.sleep(0.2)
add_result(TESTS[6][0], resp.status_code, 'Rate limiting triggered.' if rate_limited else 'No rate limiting detected.', rate_limited, TESTS[6][1])

# Save report with timestamp
report_dir = 'test reports'
os.makedirs(report_dir, exist_ok=True)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
report_filename = f'users_security_report_{timestamp}.html'
report_path = os.path.join(report_dir, report_filename)

# Write results to HTML file
html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Users Security Test Report</title>
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
        <h1>Users Security Test Report</h1>
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