import requests
import time
from datetime import datetime
import os

BASE_URL = 'http://127.0.0.1:5000/ping'
results = []
recommendations = []

TESTS = [
    ("Command Injection Test", "Attempt to inject a shell command via the host field and check if it is executed."),
    ("Input Validation Test", "Submit empty and invalid host values and check for rejection."),
    ("Error Message Consistency Test", "Check if error messages are consistent for invalid and valid hosts."),
    ("Timing Attack Test", "Measure response time for valid vs invalid host to detect timing leaks."),
    ("Output Leakage Test", "Check if sensitive system info is leaked in the output."),
    ("Rate Limiting Test", "Check if repeated ping requests trigger rate limiting or blocking."),
    ("Long/Complex Input Test", "Submit a very long or complex host value and check for errors or command execution.")
]

TEST_FIXES = {
    "Command Injection Test": "Sanitize and validate user input before passing to system commands. Use subprocess with argument lists, not shell=True.",
    "Input Validation Test": "Enforce server-side validation for hostnames/IPs. Reject empty or invalid values.",
    "Error Message Consistency Test": "Return generic error messages for failed pings to avoid information leakage.",
    "Timing Attack Test": "Ensure response times are consistent regardless of host validity. Use timeouts for system commands.",
    "Output Leakage Test": "Filter and sanitize command output before displaying to users. Avoid leaking system info.",
    "Rate Limiting Test": "Add rate limiting to prevent abuse of the ping endpoint.",
    "Long/Complex Input Test": "Enforce reasonable length and character restrictions for host input."
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

# 1. Command Injection Test
payload = {'host': '127.0.0.1; echo injected > ping_injection.txt'}
resp = requests.post(BASE_URL, data=payload)
try:
    with open('ping_injection.txt', 'r') as f:
        injected = 'injected' in f.read()
    os.remove('ping_injection.txt')
except FileNotFoundError:
    injected = False
add_result(TESTS[0][0], resp.status_code, 'Command injection succeeded!' if injected else 'No command injection.', not injected, TESTS[0][1])

# 2. Input Validation Test
payload = {'host': ''}
resp = requests.post(BASE_URL, data=payload)
empty_valid = 'Invalid' in resp.text or resp.status_code == 400
payload = {'host': '!!!invalid!!!'}
resp2 = requests.post(BASE_URL, data=payload)
invalid_valid = 'Invalid' in resp2.text or resp2.status_code == 400
add_result(TESTS[1][0], resp.status_code, 'Empty/invalid host rejected.' if empty_valid and invalid_valid else 'Empty/invalid host accepted!', empty_valid and invalid_valid, TESTS[1][1])

# 3. Error Message Consistency Test
resp1 = requests.post(BASE_URL, data={'host': '!!!invalid!!!'})
resp2 = requests.post(BASE_URL, data={'host': '127.0.0.1'})
err_consistent = (resp1.status_code == resp2.status_code) or ('Invalid' in resp1.text and 'Invalid' in resp2.text)
add_result(TESTS[2][0], resp1.status_code, 'Error messages are consistent.' if err_consistent else 'Error messages differ!', err_consistent, TESTS[2][1])

# 4. Timing Attack Test
def measure_time(host):
    start = time.time()
    requests.post(BASE_URL, data={'host': host})
    return time.time() - start
valid_time = measure_time('127.0.0.1')
invalid_time = measure_time('!!!invalid!!!')
timing_success = abs(valid_time - invalid_time) < 0.2
add_result(TESTS[3][0], 'N/A', f'Valid host time: {valid_time:.4f}s, Invalid host time: {invalid_time:.4f}s', timing_success, TESTS[3][1])

# 5. Output Leakage Test
payload = {'host': '127.0.0.1'}
resp = requests.post(BASE_URL, data=payload)
leakage = any(word in resp.text.lower() for word in ['linux', 'ubuntu', 'mac', 'windows', 'user', 'root', 'home'])
add_result(TESTS[4][0], resp.status_code, 'Sensitive info leaked!' if leakage else 'No sensitive info leaked.', not leakage, TESTS[4][1])

# 6. Rate Limiting Test
rate_limited = False
for i in range(10):
    resp = requests.post(BASE_URL, data={'host': '127.0.0.1'})
    if 'rate limit' in resp.text.lower():
        rate_limited = True
        break
    time.sleep(0.2)
add_result(TESTS[5][0], resp.status_code, 'Rate limiting triggered.' if rate_limited else 'No rate limiting detected.', rate_limited, TESTS[5][1])

# 7. Long/Complex Input Test
long_host = 'a' * 300
payload = {'host': long_host}
resp = requests.post(BASE_URL, data=payload)
long_success = 'Invalid' in resp.text or resp.status_code == 400
add_result(TESTS[6][0], resp.status_code, 'Long/complex host rejected.' if long_success else 'Long/complex host accepted!', long_success, TESTS[6][1])

# Save report with timestamp
report_dir = 'test reports'
os.makedirs(report_dir, exist_ok=True)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
report_filename = f'ping_security_report_{timestamp}.html'
report_path = os.path.join(report_dir, report_filename)

# Write results to HTML file
html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Ping Security Test Report</title>
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
        <h1>Ping Security Test Report</h1>
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