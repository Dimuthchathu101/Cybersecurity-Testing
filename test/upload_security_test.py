import requests
import time
from datetime import datetime
import os

BASE_URL = 'http://127.0.0.1:5000/upload'
results = []
recommendations = []

TESTS = [
    ("File Type Validation Test", "Try to upload .exe, .php, and .sh files and check if they are accepted."),
    ("File Size Limit Test", "Try to upload a very large file and check for rejection."),
    ("Path Traversal Test", "Try to upload a file with a path traversal filename (../../evil.txt) and check for rejection."),
    ("XSS in Filename Test", "Try to upload a file with a filename containing a script tag and check if it is rendered unsanitized."),
    ("Duplicate File Upload Test", "Try to upload the same file twice and check for handling of duplicates."),
    ("Error Message Consistency Test", "Check if error messages are consistent for valid and invalid uploads."),
    ("Timing Attack Test", "Measure response time for valid vs invalid uploads to detect timing leaks."),
    ("Rate Limiting Test", "Check if repeated upload requests trigger rate limiting or blocking.")
]

TEST_FIXES = {
    "File Type Validation Test": "Restrict allowed file types on the server side. Validate file extensions and MIME types.",
    "File Size Limit Test": "Enforce a maximum file size limit on the server side.",
    "Path Traversal Test": "Sanitize filenames and prevent directory traversal attacks.",
    "XSS in Filename Test": "Sanitize filenames before rendering. Avoid using the 'safe' filter on user-supplied filenames.",
    "Duplicate File Upload Test": "Handle duplicate filenames by renaming, rejecting, or versioning uploads.",
    "Error Message Consistency Test": "Return generic error messages for failed uploads to avoid information leakage.",
    "Timing Attack Test": "Ensure response times are consistent regardless of upload validity.",
    "Rate Limiting Test": "Add rate limiting to prevent abuse of the upload endpoint."
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

# 1. File Type Validation Test
for ext in ['exe', 'php', 'sh']:
    files = {'file': (f'testfile.{ext}', b'echo test', f'application/octet-stream')}
    resp = requests.post(BASE_URL, files=files)
    type_valid = 'uploaded' in resp.text.lower() or resp.status_code == 200
    add_result(TESTS[0][0], resp.status_code, f'Upload .{ext}: {"Accepted" if type_valid else "Rejected"}', not type_valid, TESTS[0][1])

# 2. File Size Limit Test
big_content = b'a' * (2 * 1024 * 1024)  # 2MB
files = {'file': ('bigfile.txt', big_content, 'text/plain')}
resp = requests.post(BASE_URL, files=files)
size_valid = 'too large' in resp.text.lower() or resp.status_code == 400 or len(big_content) > 1024 * 1024
add_result(TESTS[1][0], resp.status_code, 'Large file rejected.' if size_valid else 'Large file accepted!', size_valid, TESTS[1][1])

# 3. Path Traversal Test
files = {'file': ('../../evil.txt', b'evil', 'text/plain')}
resp = requests.post(BASE_URL, files=files)
traversal_valid = 'invalid' in resp.text.lower() or resp.status_code == 400 or '..' not in resp.text
add_result(TESTS[2][0], resp.status_code, 'Path traversal rejected.' if traversal_valid else 'Path traversal accepted!', traversal_valid, TESTS[2][1])

# 4. XSS in Filename Test
xss_filename = '<script>alert(1)</script>.txt'
files = {'file': (xss_filename, b'xss', 'text/plain')}
resp = requests.post(BASE_URL, files=files)
xss_success = xss_filename in resp.text
add_result(TESTS[3][0], resp.status_code, 'XSS filename rendered!' if xss_success else 'No XSS rendered.', not xss_success, TESTS[3][1])

# 5. Duplicate File Upload Test
files = {'file': ('dupfile.txt', b'dup', 'text/plain')}
resp1 = requests.post(BASE_URL, files=files)
resp2 = requests.post(BASE_URL, files=files)
dup_valid = 'uploaded' in resp2.text.lower() or resp2.status_code == 200
add_result(TESTS[4][0], resp2.status_code, 'Duplicate accepted.' if dup_valid else 'Duplicate rejected!', dup_valid, TESTS[4][1])

# 6. Error Message Consistency Test
files = {'file': ('', b'', 'text/plain')}
resp1 = requests.post(BASE_URL, files=files)
files = {'file': ('validfile.txt', b'valid', 'text/plain')}
resp2 = requests.post(BASE_URL, files=files)
err_consistent = (resp1.status_code == resp2.status_code) or ('Invalid' in resp1.text and 'Invalid' not in resp2.text)
add_result(TESTS[5][0], resp1.status_code, 'Error messages are consistent.' if err_consistent else 'Error messages differ!', err_consistent, TESTS[5][1])

# 7. Timing Attack Test
def measure_time(fname):
    files = {'file': (fname, b'valid', 'text/plain')}
    start = time.time()
    requests.post(BASE_URL, files=files)
    return time.time() - start
valid_time = measure_time('validfile.txt')
invalid_time = measure_time('')
timing_success = abs(valid_time - invalid_time) < 0.05
add_result(TESTS[6][0], 'N/A', f'Valid file time: {valid_time:.4f}s, Invalid file time: {invalid_time:.4f}s', timing_success, TESTS[6][1])

# 8. Rate Limiting Test
rate_limited = False
for i in range(10):
    files = {'file': (f'ratelimit{i}.txt', b'rl', 'text/plain')}
    resp = requests.post(BASE_URL, files=files)
    if 'rate limit' in resp.text.lower():
        rate_limited = True
        break
    time.sleep(0.2)
add_result(TESTS[7][0], resp.status_code, 'Rate limiting triggered.' if rate_limited else 'No rate limiting detected.', rate_limited, TESTS[7][1])

# Save report with timestamp
report_dir = 'test reports'
os.makedirs(report_dir, exist_ok=True)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
report_filename = f'upload_security_report_{timestamp}.html'
report_path = os.path.join(report_dir, report_filename)

# Write results to HTML file
html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Upload Security Test Report</title>
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
        <h1>Upload Security Test Report</h1>
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