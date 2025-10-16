# Information disclosure on debug page — Apprentice

**Status:** Solved

---

## Goal
Find a debug page or endpoint that shows internal info (errors, config, tokens, or user data). Use what you find to get the lab flag.

---

## Steps I took (simple, step-by-step)

1. **Look for debug pages**
   - Try common debug paths like `/debug`, `/status`, `/_debug`, `/health`, `/info`, `/admin/debug`, or `/phpinfo.php`.
   - Check `robots.txt`, sitemap, and guessable URLs from the site structure.

2. **Open the debug page**
   - Visit the page in a browser or curl it:
     ```bash
     curl -s -i "https://TARGET/debug"
     ```
   - Read the whole page — some show stack traces, env vars, source paths, or keys.

3. **Check the info shown**
   - Look for environment variables, config values, API keys, database names, user lists, or full stack traces.
   - Copy anything that looks like a secret or an internal link.

4. **Try using the info**
   - If you find a token or admin username, try it on admin endpoints or API calls.
   - If you see a filepath or backup name, try requesting that file (`/backup/config.yml`, `/old/config.php`, etc.).
   - Example:
     ```bash
     curl -s "https://TARGET/backup/config.yml"
     ```

5. **Get the flag**
   - Use the discovered secret or admin route to access the page or API that returns the flag.
   - Save the exact request that returned the flag.

---

## What to put in your README
- The debug URL you found (or how you found it).  
- The exact output you saw on the debug page (redact secrets).  
- The follow-up request you used to get the flag and the response.

---

## Short example
- Found: `GET /debug` → shows `ENV=production`, `DB_HOST=localhost`, and `ADMIN_TOKEN=abc123`.  
- Used: `GET /admin?token=abc123` → returned `{"flag":"FLAG-..."}`.  
- Result: flag retrieved.

---

## Why this works
Developers sometimes leave debug pages enabled on production. Those pages can leak config, tokens, or data that attackers can reuse.

---

## How to fix it (short)
- Disable debug pages in production builds.  
- Restrict access to debug endpoints (VPN, IP allowlist, or auth).  
- Remove sensitive data from debug output.  
- Keep a separate staging environment for debugging.

---

## Notes
- Don’t publish real keys or tokens in a public repo; replace them with `<REDACTED>`.  
- Keep steps short and repeatable so you can show how you solved the lab.
