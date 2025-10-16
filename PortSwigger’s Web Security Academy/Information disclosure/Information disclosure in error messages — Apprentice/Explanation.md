# Information disclosure in error messages — Apprentice

**Status:** Solved

---

## Goal
Make the app show an error that leaks internal info (stack traces, file paths, SQL errors, hidden endpoints). Use that info to get the lab flag.

---

## Steps I took (easy, step-by-step)

1. **Look around the app**
   - Open the site and try pages/forms (search, item pages, upload, etc.).
   - Note parameters that change behavior (like `id`, `page`, `user`).

2. **Cause an error**
   - Send inputs that the server might not expect: missing fields, very long text, or wrong types (string instead of number).
   - Quick example:
     ```bash
     curl -s -i "https://TARGET/?id=not-a-number"
     ```
   - Also tried removing expected query params and sending bad JSON.

3. **Read the error message**
   - When the server returns an error page or JSON, read it fully. Look for any file paths, line numbers, SQL messages, or internal URL names.
   - Example (redacted):
     ```
     Error: Unexpected token in JSON at position 12
       at JSON.parse (<anonymous>)
       at /var/www/app/controllers/itemController.js:42:18
     ```
   - Save the exact lines you see — they point to where to look next.

4. **Follow the clue**
   - If you see a path or file name, try to request that file or nearby paths (common places: `/data/config.json`, `/backup/`, `/old/`).
   - Example:
     ```bash
     curl -s "https://TARGET/data/config.json"
     ```
   - The file might contain a token, admin user, or the flag.

5. **Get the flag**
   - Use the found token or endpoint to access the admin page or API that returns the flag.
   - Save the exact request that gave you the flag.

---

## What to include in your README
- The request that caused the error (method, URL, params).  
- The full error text you saw (redact secrets).  
- The follow-up request that fetched the leaked file or endpoint and the response that had the flag.

---

## Short example
- Trigger: `GET /item?id=not-a-number` → server shows stack trace with `/var/www/app/controllers/itemController.js`.  
- Follow-up: `GET /data/config.json` → returns `{"admin_token":"abc123", "flag":"FLAG-..."}`.  
- Result: used `admin_token` to fetch flag page.

---

## Why this works
The app showed internal error details to users. Those details reveal files, endpoints, or tokens that should be private.

---

## How to fix it (short)
- Don’t show full stack traces or internal errors to users.  
- Log full errors on the server only. Show a simple generic error message to users (e.g., “Something went wrong”).  
- Protect backup and config files, and disable directory listing.  
- Validate inputs so the server doesn’t throw unexpected exceptions.

---

## Notes
- Never paste real secrets into a public repo. Replace them with `<REDACTED>` if you include sample outputs.  
- Keep the exact requests in the README so you can repeat the steps reliably.

