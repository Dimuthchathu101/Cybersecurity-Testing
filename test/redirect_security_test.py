import requests
import time
from datetime import datetime
import os

BASE_URL = 'http://127.0.0.1:5000/redirect'
results = []
recommendations = []

TESTS = [
    ("Open Redirect (External URL) Test", "Redirect to an external URL and check if the redirect occurs."),
    ("Open Redirect (Protocol-Relative) Test", "Redirect to a protocol-relative URL (//evil.com) and check if the redirect occurs."),
    ("Open Redirect (Internal Path) Test", "Redirect to an internal path and check if the redirect occurs."),
    ("Input Validation Test", "Submit empty or invalid next parameter and check for rejection or error."),
    ("Error Message Consistency Test", "Check if error messages are consistent for valid and invalid next parameters."),
    ("Timing Attack Test", "Measure response time for valid vs invalid next parameter to detect timing leaks."),
    ("Output Leakage Test", "Check if the redirect URL is leaked in the response body or headers.")
]

TEST_FIXES = {
    "Open Redirect (External URL) Test": "Validate and restrict redirect destinations to trusted domains only.",
    "Open Redirect (Protocol-Relative) Test": "Validate and restrict redirect destinations to trusted domains only.",
    "Open Redirect (Internal Path) Test": "Ensure only safe internal paths are allowed for redirects.",
    "Input Validation Test": "Validate the next parameter and reject empty or malformed values.",
    "Error Message Consistency Test": "Return generic error messages for invalid redirects to avoid information leakage.",
    "Timing Attack Test": "Ensure response times are consistent regardless of next parameter validity.",
    "Output Leakage Test": "Do not leak redirect URLs in response bodies or error messages."
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

# 1. Open Redirect (External URL) Test
resp = requests.get(BASE_URL, params={'next': 'https://example.com'}, allow_redirects=False)
external_success = resp.status_code in (301, 302) and 'example.com' in resp.headers.get('Location', '')
add_result(TESTS[0][0], resp.status_code, f"Redirected to: {resp.headers.get('Location', '')}", not external_success, TESTS[0][1])

# 2. Open Redirect (Protocol-Relative) Test
resp = requests.get(BASE_URL, params={'next': '//evil.com'}, allow_redirects=False)
proto_success = resp.status_code in (301, 302) and 'evil.com' in resp.headers.get('Location', '')
add_result(TESTS[1][0], resp.status_code, f"Redirected to: {resp.headers.get('Location', '')}", not proto_success, TESTS[1][1])

# 3. Open Redirect (Internal Path) Test
resp = requests.get(BASE_URL, params={'next': '/users'}, allow_redirects=False)
internal_success = resp.status_code in (301, 302) and '/users' in resp.headers.get('Location', '')
add_result(TESTS[2][0], resp.status_code, f"Redirected to: {resp.headers.get('Location', '')}", internal_success, TESTS[2][1])

# 4. Input Validation Test
resp = requests.get(BASE_URL, params={'next': ''}, allow_redirects=False)
input_valid = resp.status_code == 400 or 'No next parameter' in resp.text
add_result(TESTS[3][0], resp.status_code, 'Empty/invalid next rejected.' if input_valid else 'Empty/invalid next accepted!', input_valid, TESTS[3][1])

# 5. Error Message Consistency Test
resp1 = requests.get(BASE_URL, params={'next': ''}, allow_redirects=False)
resp2 = requests.get(BASE_URL, params={'next': '/users'}, allow_redirects=False)
err_consistent = (resp1.status_code == resp2.status_code) or ('No next parameter' in resp1.text and 'No next parameter' not in resp2.text)
add_result(TESTS[4][0], resp1.status_code, 'Error messages are consistent.' if err_consistent else 'Error messages differ!', err_consistent, TESTS[4][1])

# 6. Timing Attack Test
def measure_time(nextval):
    start = time.time()
    requests.get(BASE_URL, params={'next': nextval}, allow_redirects=False)
    return time.time() - start
valid_time = measure_time('/users')
invalid_time = measure_time('')
timing_success = abs(valid_time - invalid_time) < 0.05
add_result(TESTS[5][0], 'N/A', f'Valid next time: {valid_time:.4f}s, Invalid next time: {invalid_time:.4f}s', timing_success, TESTS[5][1])

# 7. Output Leakage Test
resp = requests.get(BASE_URL, params={'next': 'https://example.com'}, allow_redirects=False)
leakage = 'example.com' in resp.text or 'example.com' in str(resp.headers)
add_result(TESTS[6][0], resp.status_code, 'Redirect URL leaked!' if leakage else 'No redirect URL leaked.', not leakage, TESTS[6][1])

# Save report with timestamp
report_dir = 'test reports'
os.makedirs(report_dir, exist_ok=True)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
report_filename = f'redirect_security_report_{timestamp}.html'
report_path = os.path.join(report_dir, report_filename)

# Write results to HTML file
html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Redirect Security Test Report</title>
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
        <h1>Redirect Security Test Report</h1>
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