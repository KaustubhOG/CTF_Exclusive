# Source code disclosure via backup files — Apprentice

**Status:** Solved

---

## Goal
Find a backup or old file (like `.bak`, `.old`, `.zip`, `.tar`, or `.bak.php`) left on the server that contains source code or config. Use that file to get the flag.

---

## Steps I took (simple, step-by-step)

1. **Look for common backup names**
   - Try guessing files and folders: `.bak`, `.old`, `.swp`, `backup.zip`, `site.bak`, `index.php.bak`, `config.php~`, `app.tar.gz`, etc.
   - Check likely paths: root (`/`), `/backup`, `/old`, `/archive`, `/files`, `/uploads`.

2. **Probe with curl or browser**
   - Request the guessed file directly:
     ```bash
     curl -s -i "https://TARGET/index.php.bak"
     ```
   - Also try directory indexes if allowed: `https://TARGET/backup/`

3. **Download and inspect the file**
   - If you get a file, save it and open it in a text editor.
   - Look for credentials, API keys, admin passwords, or any code that reveals hidden endpoints or logic.

4. **Use what's inside**
   - If the file contains an admin password or token, use it to log in or call an API.
   - If it contains a path or an internal endpoint, request that endpoint.
   - Example actions:
     ```bash
     curl -s "https://TARGET/admin?password=found_password"
     ```
     or
     ```bash
     curl -s "https://TARGET/internal/config.php"
     ```

5. **Get the flag**
   - Access the page or API that returns the flag using the found info.
   - Save the exact request that returned the flag.

---

## What to include in your README
- The exact filename or URL you found (or how you guessed it).  
- The important lines from the file you downloaded (redact real secrets).  
- The request that used that info to fetch the flag and the response.

---

## Short example
- Found: `GET /index.php.bak` → file contains `ADMIN_PASS="letmein123"` and an internal endpoint `/admin/secret`.  
- Used: `GET /admin/secret?pass=letmein123` → returned `{"flag":"FLAG-..."}`.  
- Result: flag retrieved.

---

## Why this works
Developers sometimes leave backup files or old uploads on the server. Those files may contain full source code or secrets that let you access admin-only features.

---

## How to fix it (short)
- Don’t leave backups on public web servers. Keep them off the web root.  
- Remove leftover editor swap files and backup files before deployment.  
- Use proper config management and environment variables, not checked-in secrets.  
- Disable directory listing and restrict access to sensitive paths.

---

## Notes
- Never commit real passwords or keys to a public repo. Replace them with `<REDACTED>` if you show examples.  
- Keep the exact commands and file names in the README so others can reproduce the steps if needed.
