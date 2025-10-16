# Authentication bypass via information disclosure — Apprentice

**Status:** Solved

---

## Goal
Find info leaked by the app (errors, files, debug pages) that lets you skip normal login or access a protected page. Use that info to get the lab flag.

---

## Steps I took (easy, step-by-step)

1. **Explore the site**
   - Open the public pages and try the login or protected pages to see how they behave.
   - Note any parameters or URLs that look like they control access (e.g., `token`, `auth`, `user`, `role`).

2. **Look for leaks**
   - Try things that make the app show internal info: cause errors, visit `/debug`, check for backup files, or try odd inputs.
   - Also check predictable files or paths (`/config`, `/backup`, `/.git`, `/debug`).

3. **Find a useful secret**
   - When something leaks (error message, file, debug output), look for tokens, session IDs, admin names, or hints about how auth works.
   - Save the exact string you find (token, cookie, or password).

4. **Try to bypass auth**
   - Use the leaked token or value directly in the request (query string, header, or cookie), or try to call any internal endpoint shown.
   - Examples:
     ```bash
     # token in query
     curl -s "https://TARGET/admin?token=FOUND_TOKEN"

     # token as header
     curl -s -H "Authorization: Bearer FOUND_TOKEN" "https://TARGET/admin"
     ```

5. **If a role or flag parameter is visible**
   - Try changing a visible parameter like `role=user` → `role=admin`, or request an internal endpoint revealed in the leak.

6. **Get the flag**
   - Once you can access the admin/protected page or API, fetch the flag and save the exact request that returned it.

---

## What to put in your README
- How you found the leaked info (which page/file caused it).  
- The exact leaked value (redact if sensitive) and where you put it (header, cookie, query).  
- The request that returned the flag and the response.

---

## Short example
- Found: error page showed `AUTH_TOKEN=abc123` in a config path.  
- Used:
  ```bash
  curl -s -H "Authorization: Bearer abc123" "https://TARGET/admin"
