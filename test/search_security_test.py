import requests
import time
from datetime import datetime
import os

BASE_URL = 'http://127.0.0.1:5000/search'
results = []
recommendations = []

TESTS = [
    ("SQL Injection Test", "Attempt SQL injection in the search query and check for errors or data leakage."),
    ("Input Validation Test", "Submit empty, long, or invalid search queries and check for rejection."),
    ("XSS in Search Query Test", "Submit a search query with a script tag and check if it is rendered unsanitized."),
    ("Error Message Consistency Test", "Check if error messages are consistent for valid and invalid queries."),
    ("Timing Attack Test", "Measure response time for valid vs invalid queries to detect timing leaks."),
    ("Output Leakage Test", "Check if sensitive system info or SQL errors are leaked in the output."),
    ("Rate Limiting Test", "Check if repeated search requests trigger rate limiting or blocking.")
]

TEST_FIXES = {
    "SQL Injection Test": "Use parameterized queries for all database operations.",
    "Input Validation Test": "Enforce server-side validation for search queries. Reject empty, overly long, or invalid values.",
    "XSS in Search Query Test": "Sanitize user input before rendering. Use Jinja2's default escaping and avoid using the 'safe' filter on user content.",
    "Error Message Consistency Test": "Return generic error messages for failed searches to avoid information leakage.",
    "Timing Attack Test": "Ensure response times are consistent regardless of query validity.",
    "Output Leakage Test": "Filter and sanitize output before displaying to users. Avoid leaking system info or SQL errors.",
    "Rate Limiting Test": "Add rate limiting to prevent abuse of the search endpoint."
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

# 1. SQL Injection Test
payload = {'query': "' OR 1=1 --"}
resp = requests.post(BASE_URL, data=payload)
sqli_success = 'error' not in resp.text.lower() and 'sqlite' not in resp.text.lower()
add_result(TESTS[0][0], resp.status_code, 'No SQL error or leakage detected.' if sqli_success else 'Potential SQL error or leakage!', sqli_success, TESTS[0][1])

# 2. Input Validation Test
payload = {'query': ''}
resp = requests.post(BASE_URL, data=payload)
empty_valid = 'Invalid' in resp.text or resp.status_code == 400
long_query = 'a' * 600
resp2 = requests.post(BASE_URL, data={'query': long_query})
long_valid = 'Invalid' in resp2.text or resp2.status_code == 400
add_result(TESTS[1][0], resp.status_code, 'Empty/long query rejected.' if empty_valid and long_valid else 'Empty/long query accepted!', empty_valid and long_valid, TESTS[1][1])

# 3. XSS in Search Query Test
xss_payload = '<script>alert(1)</script>'
resp = requests.post(BASE_URL, data={'query': xss_payload})
xss_success = xss_payload in resp.text
add_result(TESTS[2][0], resp.status_code, 'XSS payload rendered!' if xss_success else 'No XSS rendered.', not xss_success, TESTS[2][1])

# 4. Error Message Consistency Test
resp1 = requests.post(BASE_URL, data={'query': ''})
resp2 = requests.post(BASE_URL, data={'query': 'admin'})
err_consistent = (resp1.status_code == resp2.status_code) or ('Invalid' in resp1.text and 'Invalid' not in resp2.text)
add_result(TESTS[3][0], resp1.status_code, 'Error messages are consistent.' if err_consistent else 'Error messages differ!', err_consistent, TESTS[3][1])

# 5. Timing Attack Test
def measure_time(query):
    start = time.time()
    requests.post(BASE_URL, data={'query': query})
    return time.time() - start
valid_time = measure_time('admin')
invalid_time = measure_time("' OR 1=1 --")
timing_success = abs(valid_time - invalid_time) < 0.05
add_result(TESTS[4][0], 'N/A', f'Valid query time: {valid_time:.4f}s, SQLi query time: {invalid_time:.4f}s', timing_success, TESTS[4][1])

# 6. Output Leakage Test
payload = {'query': "' OR 1=1 --"}
resp = requests.post(BASE_URL, data=payload)
leakage = any(word in resp.text.lower() for word in ['sqlite', 'error', 'traceback'])
add_result(TESTS[5][0], resp.status_code, 'Sensitive info leaked!' if leakage else 'No sensitive info leaked.', not leakage, TESTS[5][1])

# 7. Rate Limiting Test
rate_limited = False
for i in range(10):
    resp = requests.post(BASE_URL, data={'query': 'admin'})
    if 'rate limit' in resp.text.lower():
        rate_limited = True
        break
    time.sleep(0.2)
add_result(TESTS[6][0], resp.status_code, 'Rate limiting triggered.' if rate_limited else 'No rate limiting detected.', rate_limited, TESTS[6][1])

# Save report with timestamp
report_dir = 'test reports'
os.makedirs(report_dir, exist_ok=True)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
report_filename = f'search_security_report_{timestamp}.html'
report_path = os.path.join(report_dir, report_filename)

# Write results to HTML file
html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Search Security Test Report</title>
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
        <h1>Search Security Test Report</h1>
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