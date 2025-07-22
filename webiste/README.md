# Flask Security Demo

This project contains a basic Flask website with intentional security vulnerabilities for educational and testing purposes.

## How to Run

1. Navigate to the project directory:
   ```bash
   cd webiste
   ```
2. Activate the virtual environment:
   ```bash
   source venv/bin/activate
   ```
3. Install dependencies (if needed):
   ```bash
   pip3 install flask --break-system-packages
   ```
4. Run the Flask app:
   ```bash
   python3 app.py
   ```
5. Open your browser and go to:
   ```
   http://127.0.0.1:5000/
   ```

## Database Location
- The SQLite database file is located at: `webiste/users.db`
- It is created automatically when you run the app for the first time.

## How SQLite is Used
SQLite is the backend database for all demo scenarios. Here’s how it is used in each feature:

| Feature/Route             | SQLite Table Used | SQL Operation(s)         |
|--------------------------|------------------|--------------------------|
| `/login`, `/brute-login` | users            | SELECT                   |
| `/comments`              | comments         | INSERT, SELECT           |
| `/users`, `/profile`     | users            | SELECT                   |
| `/search`                | users            | SELECT (with LIKE)       |
| `/change-password`       | users            | UPDATE                   |

- **User Authentication:** Login forms use SQL queries to check credentials in the `users` table.
- **Stored XSS:** Comments are inserted and fetched from the `comments` table.
- **IDOR:** User lists and profiles are queried from the `users` table.
- **SQL Injection:** The search form uses a vulnerable SQL query on the `users` table.
- **CSRF:** The password change form updates the `users` table.
- All persistent data is stored in `users.db`.

## Vulnerability Demo Routes
- `/` or `/login` — SQL Injection login
- `/comments` — Stored XSS
- `/upload` — File upload vulnerability
- `/users` — User list (IDOR)
- `/profile?id=...` — Profile (IDOR)
- `/redirect-demo` — Open redirect demo
- `/search` — SQL Injection search
- `/change-password` — CSRF demo
- `/crash` — Information disclosure (stack trace)
- `/weak-login` — Weak session management
- `/ping` — Command injection
- `/brute-login` — Brute force login

## Automated Login Security Testing

A separate folder `test` contains an advanced login security test script:
- **Script:** `test/login_security_test.py`
- **How to run:**
  1. Navigate to the `test` folder:
     ```bash
     cd ../test
     ```
  2. Create and activate the virtual environment (if not already):
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
  3. Install dependencies:
     ```bash
     pip3 install requests --break-system-packages
     ```
  4. Run the script:
     ```bash
     python3 login_security_test.py
     ```
- **What it does:**
  - Tests for SQL injection, brute force, input validation, rate limiting, timing attacks, error message consistency, CSRF protection, and session fixation on the login page.
  - Generates a detailed, attractive HTML report in `test/test reports/` with a timestamped filename.
  - The report includes color-coded results, test descriptions, and for each failed test, a clear "How to fix" recommendation.

**Note:** This app is for educational purposes only. Do not deploy in production.