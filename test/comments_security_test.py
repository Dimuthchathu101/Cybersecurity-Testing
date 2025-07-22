import requests
import time
from datetime import datetime
import os

BASE_URL = 'http://127.0.0.1:5000/comments'
results = []
recommendations = []

TESTS = [
    ("XSS Injection Test", "Submit a comment with a script tag and check if it is rendered unsanitized."),
    ("SQL Injection Test", "Submit a comment with SQL injection payload and check for errors or data leakage."),
    ("Spam/Duplicate Comment Test", "Submit the same comment twice within 1 minute and check for spam prevention."),
    ("Long Comment Test", "Submit a comment longer than 500 characters and check for rejection."),
    ("Reply Threading Test", "Submit a reply to a comment and check if it appears nested."),
    ("Upvote/Downvote Abuse Test", "Try to upvote/downvote the same comment multiple times as the same user."),
    ("Unauthorized Delete Test", "Try to delete a comment as a different user and check for rejection.")
]

TEST_FIXES = {
    "XSS Injection Test": "Sanitize user input before rendering. Use Jinja2's default escaping and avoid using the 'safe' filter on user content.",
    "SQL Injection Test": "Use parameterized queries for all database operations.",
    "Spam/Duplicate Comment Test": "Implement rate limiting and duplicate comment checks.",
    "Long Comment Test": "Enforce server-side length validation for comments.",
    "Reply Threading Test": "Ensure replies are properly linked to parent comments and displayed nested.",
    "Upvote/Downvote Abuse Test": "Prevent multiple votes per user per comment (by username or session).",
    "Unauthorized Delete Test": "Check that only the comment owner or admin can delete a comment."
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

# 1. XSS Injection Test
xss_payload = '<script>alert(1)</script>'
resp = requests.post(BASE_URL, data={'username': 'xssuser', 'comment': xss_payload})
page = requests.get(BASE_URL).text
xss_success = xss_payload in page
add_result(TESTS[0][0], resp.status_code, f'Payload present in page: {xss_success}', not xss_success, TESTS[0][1])

# 2. SQL Injection Test
sqli_payload = "test'); DROP TABLE comments;--"
resp = requests.post(BASE_URL, data={'username': 'sqluser', 'comment': sqli_payload})
page = requests.get(BASE_URL).text
sqli_success = 'error' not in page.lower() and 'sqlite' not in page.lower()
add_result(TESTS[1][0], resp.status_code, 'No SQL error or leakage detected.' if sqli_success else 'Potential SQL error or leakage!', sqli_success, TESTS[1][1])

# 3. Spam/Duplicate Comment Test
spam_payload = 'spam test comment'
resp1 = requests.post(BASE_URL, data={'username': 'spamuser', 'comment': spam_payload})
resp2 = requests.post(BASE_URL, data={'username': 'spamuser', 'comment': spam_payload})
spam_success = 'again so soon' in resp2.text
add_result(TESTS[2][0], resp2.status_code, 'Duplicate comment blocked.' if spam_success else 'Duplicate comment allowed!', spam_success, TESTS[2][1])

# 4. Long Comment Test
long_comment = 'a' * 600
resp = requests.post(BASE_URL, data={'username': 'longuser', 'comment': long_comment})
long_success = '1-500 characters' in resp.text
add_result(TESTS[3][0], resp.status_code, 'Long comment rejected.' if long_success else 'Long comment accepted!', long_success, TESTS[3][1])

# 5. Reply Threading Test
parent_payload = 'parent comment for reply test'
resp = requests.post(BASE_URL, data={'username': 'threaduser', 'comment': parent_payload})
page = requests.get(BASE_URL).text
import re as regex
match = regex.search(r'name="parent_id" value="(\d+)"', page)
reply_success = False
if match:
    parent_id = match.group(1)
    reply_payload = 'this is a reply'
    resp = requests.post(BASE_URL, data={'username': 'threaduser', 'comment': reply_payload, 'parent_id': parent_id})
    page = requests.get(BASE_URL).text
    reply_success = reply_payload in page and parent_payload in page
add_result(TESTS[4][0], resp.status_code, 'Reply appears nested.' if reply_success else 'Reply not nested or missing!', reply_success, TESTS[4][1])

# 6. Upvote/Downvote Abuse Test
# Upvote a comment, then try again as same user
page = requests.get(BASE_URL).text
match = regex.search(r'name="comment_id" value="(\d+)"', page)
vote_success = False
if match:
    comment_id = match.group(1)
    resp1 = requests.post(BASE_URL, data={'action': 'upvote', 'comment_id': comment_id, 'username': 'voteuser'})
    resp2 = requests.post(BASE_URL, data={'action': 'upvote', 'comment_id': comment_id, 'username': 'voteuser'})
    vote_success = 'already voted' in resp2.text
add_result(TESTS[5][0], resp2.status_code if match else 200, 'Multiple votes blocked.' if vote_success else 'Multiple votes allowed!', vote_success, TESTS[5][1])

# 7. Unauthorized Delete Test
# Try to delete a comment as a different user
if match:
    resp = requests.post(BASE_URL, data={'action': 'delete', 'comment_id': comment_id, 'username': 'notowner'})
    delete_success = 'only delete your own' in resp.text
else:
    delete_success = False
add_result(TESTS[6][0], resp.status_code if match else 200, 'Unauthorized delete blocked.' if delete_success else 'Unauthorized delete allowed!', delete_success, TESTS[6][1])

# Save report with timestamp
report_dir = 'test reports'
os.makedirs(report_dir, exist_ok=True)
timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
report_filename = f'comments_security_report_{timestamp}.html'
report_path = os.path.join(report_dir, report_filename)

# Write results to HTML file
html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Comments Security Test Report</title>
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
        <h1>Comments Security Test Report</h1>
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