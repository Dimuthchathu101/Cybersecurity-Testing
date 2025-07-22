import requests
import time
from datetime import datetime
import os

BASE_URL = 'http://127.0.0.1:5000/register'
results = []
recommendations = []

TESTS = [
    ("Input Validation Test", "Submit invalid/empty username, email, and password and check for rejection."),
    ("Duplicate Username/Email Test", "Try to register with an existing username or email and check for rejection."),
    ("Password Policy Test", "Check if the password must meet minimum length or complexity requirements."),
    ("Role Escalation Test", "Try to register as admin when an admin already exists and check for rejection."),
    ("CSRF Protection Test", "Check if the registration form includes a CSRF token field."),
    ("Timing Attack Test", "Measure response time for valid vs invalid registration to detect timing leaks."),
    ("Error Message Consistency Test", "Check if error messages are consistent for different invalid inputs.")
]

TEST_FIXES = {
    "Input Validation Test": "Validate and sanitize all user input. Enforce proper username, email, and password format.",
    "Duplicate Username/Email Test": "Check for existing usernames and emails before registration and return a generic error message.",
    "Password Policy Test": "Enforce strong password policies (length, complexity, etc.) on the server side.",
    "Role Escalation Test": "Allow admin registration only if no admin exists. Otherwise, restrict to user role.",
    "CSRF Protection Test": "Implement CSRF protection using tokens in all forms that modify state.",
    "Timing Attack Test": "Ensure response times are consistent regardless of input validity. Use constant-time comparison functions.",
    "Error Message Consistency Test": "Return generic error messages for failed registration to avoid information leakage."
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

# 1. Input Validation Test
resp = requests.post(BASE_URL, data={"username": "", "email": "", "password": "", "confirm": "", "role": "user"})
input_valid = 'Invalid' in resp.text or resp.status_code == 400
add_result(TESTS[0][0], resp.status_code, 'Invalid input rejected.' if input_valid else 'Invalid input accepted!', input_valid, TESTS[0][1])

# 2. Duplicate Username/Email Test
username = f"dupuser_{int(time.time())}"
email = f"{username}@example.com"
password = "TestPass123!"
# Register once
requests.post(BASE_URL, data={"username": username, "email": email, "password": password, "confirm": password, "role": "user"})
# Try duplicate
resp = requests.post(BASE_URL, data={"username": username, "email": email, "password": password, "confirm": password, "role": "user"})
dup_valid = 'already exists' in resp.text.lower() or resp.status_code == 400
add_result(TESTS[1][0], resp.status_code, 'Duplicate rejected.' if dup_valid else 'Duplicate accepted!', dup_valid, TESTS[1][1])

# 3. Password Policy Test
resp = requests.post(BASE_URL, data={"username": f"pwuser_{int(time.time())}", "email": f"pwuser_{int(time.time())}@example.com", "password": "a", "confirm": "a", "role": "user"})
policy_success = 'at least' in resp.text.lower() or 'invalid' in resp.text.lower() or 'error' in resp.text.lower()
add_result(TESTS[2][0], resp.status_code, 'Weak password rejected.' if policy_success else 'Weak password accepted!', policy_success, TESTS[2][1])

# 4. Role Escalation Test
# Try to register as admin (should only be allowed if no admin exists)
resp = requests.post(BASE_URL, data={"username": f"admin_{int(time.time())}", "email": f"admin_{int(time.time())}@example.com", "password": "TestPass123!", "confirm": "TestPass123!", "role": "admin"})
role_success = 'admin' not in resp.text.lower() or 'not allowed' in resp.text.lower() or resp.status_code == 400
add_result(TESTS[3][0], resp.status_code, 'Admin registration blocked.' if role_success else 'Admin registration allowed!', role_success, TESTS[3][1])

# 5. CSRF Protection Test
resp = requests.get(BASE_URL)
csrf_success = 'csrf' in resp.text.lower()
add_result(TESTS[4][0], resp.status_code, 'CSRF token found.' if csrf_success else 'No CSRF token found.', csrf_success, TESTS[4][1])

# 6. Timing Attack Test
def measure_time(username, email, password):
    start = time.time()
    requests.post(BASE_URL, data={"username": username, "email": email, "password": password, "confirm": password, "role": "user"})
    return time.time() - start
valid_time = measure_time(f"timinguser_{int(time.time())}", f"timinguser_{int(time.time())}@example.com", "TestPass123!")
invalid_time = measure_time("", "", "")
timing_success = abs(valid_time - invalid_time) < 0.05
add_result(TESTS[5][0], 'N/A', f'Valid registration time: {valid_time:.4f}s, Invalid registration time: {invalid_time:.4f}s', timing_success, TESTS[5][1])

# 7. Error Message Consistency Test
resp1 = requests.post(BASE_URL, data={"username": "", "email": "", "password": "", "confirm": "", "role": "user"})
resp2 = requests.post(BASE_URL, data={"username": f"emuser_{int(time.time())}", "email": f"emuser_{int(time.time())}@example.com", "password": "TestPass123!", "confirm": "TestPass123!", "role": "user"})
err_consistent = (resp1.text == resp2.text) or ('Invalid' in resp1.text and 'Invalid' not in resp2.text)
add_result(TESTS[6][0], resp1.status_code, 'Error messages are consistent.' if err_consistent else 'Error messages differ!', err_consistent, TESTS[6][1])

# Save report with timestamp
report_dir = 'test reports'
os.makedirs(report_dir, exist_ok=True)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
report_filename = f'register_security_report_{timestamp}.html'
report_path = os.path.join(report_dir, report_filename)

# Write results to HTML file
html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Register Security Test Report</title>
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
        <h1>Register Security Test Report</h1>
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