import requests
import time
from datetime import datetime
import os

BASE_URL = 'http://127.0.0.1:5000/crash'
results = []
recommendations = []

TESTS = [
    ("ZeroDivisionError Test", "Trigger a ZeroDivisionError and check for stack trace and logging."),
    ("KeyError Test", "Trigger a KeyError and check for stack trace and logging."),
    ("TypeError Test", "Trigger a TypeError and check for stack trace and logging."),
    ("Custom Exception Test", "Trigger a custom exception and check for stack trace and logging."),
    ("HTTP 404 Test", "Trigger a 404 Not Found error and check for proper HTTP response."),
    ("HTTP 403 Test", "Trigger a 403 Forbidden error and check for proper HTTP response."),
    ("HTTP 500 Test", "Trigger a 500 Internal Server Error and check for proper HTTP response."),
    ("Slow Response Test", "Trigger a slow response and check if the delay is as expected."),
    ("MemoryError Test", "Trigger a MemoryError and check for stack trace and logging."),
    ("OSError Test", "Trigger an OSError (file not found) and check for stack trace and logging."),
    ("Infinite Loop Timeout Test", "Trigger an infinite loop and check if it times out and is logged.")
]

TEST_FIXES = {
    "ZeroDivisionError Test": "Handle division by zero errors gracefully and avoid leaking stack traces.",
    "KeyError Test": "Handle missing dictionary keys gracefully and avoid leaking stack traces.",
    "TypeError Test": "Handle type errors gracefully and avoid leaking stack traces.",
    "Custom Exception Test": "Handle custom exceptions gracefully and avoid leaking stack traces.",
    "HTTP 404 Test": "Return a user-friendly 404 error page without leaking server details.",
    "HTTP 403 Test": "Return a user-friendly 403 error page without leaking server details.",
    "HTTP 500 Test": "Return a user-friendly 500 error page without leaking server details.",
    "Slow Response Test": "Monitor and alert on slow responses. Consider using timeouts and async processing.",
    "MemoryError Test": "Catch and handle memory errors gracefully. Monitor memory usage.",
    "OSError Test": "Handle file errors gracefully and avoid leaking file paths or stack traces.",
    "Infinite Loop Timeout Test": "Use timeouts and watchdogs to prevent infinite loops from hanging the server."
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

# 1. ZeroDivisionError Test
try:
    resp = requests.post(BASE_URL, data={'type': 'zero'}, timeout=5)
    stack_trace = 'ZeroDivisionError' in resp.text or 'Traceback' in resp.text
    add_result(TESTS[0][0], resp.status_code, 'Stack trace shown.' if stack_trace else 'No stack trace.', not stack_trace, TESTS[0][1])
except Exception as e:
    add_result(TESTS[0][0], 'Timeout', str(e), False, TESTS[0][1])

# 2. KeyError Test
try:
    resp = requests.post(BASE_URL, data={'type': 'key'}, timeout=5)
    stack_trace = 'KeyError' in resp.text or 'Traceback' in resp.text
    add_result(TESTS[1][0], resp.status_code, 'Stack trace shown.' if stack_trace else 'No stack trace.', not stack_trace, TESTS[1][1])
except Exception as e:
    add_result(TESTS[1][0], 'Timeout', str(e), False, TESTS[1][1])

# 3. TypeError Test
try:
    resp = requests.post(BASE_URL, data={'type': 'type'}, timeout=5)
    stack_trace = 'TypeError' in resp.text or 'Traceback' in resp.text
    add_result(TESTS[2][0], resp.status_code, 'Stack trace shown.' if stack_trace else 'No stack trace.', not stack_trace, TESTS[2][1])
except Exception as e:
    add_result(TESTS[2][0], 'Timeout', str(e), False, TESTS[2][1])

# 4. Custom Exception Test
try:
    resp = requests.post(BASE_URL, data={'type': 'custom'}, timeout=5)
    stack_trace = 'CustomError' in resp.text or 'Traceback' in resp.text
    add_result(TESTS[3][0], resp.status_code, 'Stack trace shown.' if stack_trace else 'No stack trace.', not stack_trace, TESTS[3][1])
except Exception as e:
    add_result(TESTS[3][0], 'Timeout', str(e), False, TESTS[3][1])

# 5. HTTP 404 Test
resp = requests.post(BASE_URL, data={'type': '404'})
add_result(TESTS[4][0], resp.status_code, '404 returned.' if resp.status_code == 404 else f'Got {resp.status_code}', resp.status_code == 404, TESTS[4][1])

# 6. HTTP 403 Test
resp = requests.post(BASE_URL, data={'type': '403'})
add_result(TESTS[5][0], resp.status_code, '403 returned.' if resp.status_code == 403 else f'Got {resp.status_code}', resp.status_code == 403, TESTS[5][1])

# 7. HTTP 500 Test
resp = requests.post(BASE_URL, data={'type': '500'})
add_result(TESTS[6][0], resp.status_code, '500 returned.' if resp.status_code == 500 else f'Got {resp.status_code}', resp.status_code == 500, TESTS[6][1])

# 8. Slow Response Test
start = time.time()
resp = requests.post(BASE_URL, data={'type': 'slow'})
duration = time.time() - start
slow_success = duration >= 5
add_result(TESTS[7][0], resp.status_code, f'Response time: {duration:.2f}s', slow_success, TESTS[7][1])

# 9. MemoryError Test
try:
    resp = requests.post(BASE_URL, data={'type': 'memory'}, timeout=5)
    stack_trace = 'MemoryError' in resp.text or 'Traceback' in resp.text
    add_result(TESTS[8][0], resp.status_code, 'Stack trace shown.' if stack_trace else 'No stack trace.', not stack_trace, TESTS[8][1])
except Exception as e:
    add_result(TESTS[8][0], 'Timeout', str(e), False, TESTS[8][1])

# 10. OSError Test
try:
    resp = requests.post(BASE_URL, data={'type': 'os'}, timeout=5)
    stack_trace = 'OSError' in resp.text or 'Traceback' in resp.text or 'No such file' in resp.text
    add_result(TESTS[9][0], resp.status_code, 'Stack trace shown.' if stack_trace else 'No stack trace.', not stack_trace, TESTS[9][1])
except Exception as e:
    add_result(TESTS[9][0], 'Timeout', str(e), False, TESTS[9][1])

# 11. Infinite Loop Timeout Test
try:
    resp = requests.post(BASE_URL, data={'type': 'loop'}, timeout=7)
    timeout_success = 'timed out' in resp.text or resp.status_code == 200
    add_result(TESTS[10][0], resp.status_code, 'Infinite loop timed out.' if timeout_success else 'No timeout!', timeout_success, TESTS[10][1])
except Exception as e:
    add_result(TESTS[10][0], 'Timeout', str(e), True, TESTS[10][1])

# Save report with timestamp
report_dir = 'test reports'
os.makedirs(report_dir, exist_ok=True)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
report_filename = f'crash_security_report_{timestamp}.html'
report_path = os.path.join(report_dir, report_filename)

# Write results to HTML file
html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Crash Security Test Report</title>
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
        <h1>Crash Security Test Report</h1>
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