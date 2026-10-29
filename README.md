# Keybox

A basic local password manager built with Python, Flask, and SQLite. It supports creating a vault, unlocking it, storing a website/app name and optional URL, keeping multiple login identifiers per entry, password-only, password-plus-2FA, or 2FA-only sign-in records, generating secure passwords, adding any number of custom fields, manually marking passwords verified or unverified, deleting entries, importing JSON or CSV files, exporting the vault as JSON or CSV, searching websites, URLs, login identifiers, tags, notes, and custom fields, filtering entries by tag, and switching between light and dark themes.

## Screenshot

![Keybox password vault dashboard](img/Screenshot%202026-10-15%20175629.png)

## Run locally

1. Create and activate a virtual environment.
2. Install the dependencies: `pip install -r requirements.txt`
3. Start the app: `python app.py` (it opens the default browser automatically).
4. If the browser does not open, visit `http://127.0.0.1:54327` and create a master password.

The SQLite database is created as `passwords.sqlite3` in this folder. Set `PASSWORD_MANAGER_DB` to use another location. The master password must be at least 4 characters. Password entries, website URLs, login identifiers, tags, notes, and custom fields are encrypted together with Fernet; a key is derived from the master password using PBKDF2-HMAC-SHA256. The encryption key exists in process memory while the vault is unlocked. Restarting the app locks all sessions. There is no master-password recovery, so keep a secure backup of the database and remember the master password.

Flask's interactive debugger is enabled for local development. It can expose powerful access if reachable by others, so keep the app on localhost and never expose the development server directly to the internet. For a public deployment, disable the debugger and add production session management, HTTPS, rate limiting, and operational key handling.
