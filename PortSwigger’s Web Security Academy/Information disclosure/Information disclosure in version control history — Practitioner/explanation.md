# Information disclosure in version control history — Practitioner

**Status:** Solved

---

## Goal
Find sensitive data (secrets, passwords, tokens, or config) left in the project's version-control history (commits, old files, or `.git` folder). Use that info to get the lab flag.

---

## Steps I took (simple, step-by-step)

1. **Check for exposed VCS data**
   - Look for `.git/`, `.hg/`, `.svn/`, or any repo files accessible from the web (common paths: `/`, `/repo/`, `/backup/`, `/.git/`).
   - Try `/.git/config`, `/.git/HEAD`, or `/ .git/index` with curl or a browser.

2. **Download the repo files**
   - If `.git` is readable, grab key files:
     ```bash
     curl -s "https://TARGET/.git/HEAD" -o HEAD
     curl -s "https://TARGET/.git/config" -o config
     ```
   - If you can, download the pack files or individual objects and reconstruct the repo (or use a public tool to do it).

3. **Search commit history**
   - Look for commits that contain secrets: passwords, tokens, API keys, or config files that were removed later.
   - If you grabbed objects, run `git` commands locally to recover history:
     ```bash
     git init recovered
     # move objects into recovered/.git/objects and run
     git log --all -p
     ```
   - If you can't fully reconstruct, grep through downloaded files for keywords like `PASSWORD`, `TOKEN`, `SECRET`, `AWS`, `DB_`, `KEY`.

4. **Find useful secrets**
   - Note any credentials, tokens, or config that can be used to log in or call admin APIs.
   - Also check for old endpoints or admin usernames that were later removed.

5. **Use the secret to get the flag**
   - Try the found credential or token on admin pages, API endpoints, or config URLs.
   - Example:
     ```bash
     curl -s -H "Authorization: Bearer FOUND_TOKEN" "https://TARGET/admin"
     ```
   - Save the exact request that returned the flag.

---

## What to include in your README
- How you found the VCS data (URL or method).  
- The exact commit or file that had the secret (redact real secrets).  
- The request that used the secret and returned the flag.

---

## Short example
- Found: readable `.git/` directory. Recovered a commit where `config.json` had `"admin_token":"abc123"`.  
- Used:
  ```bash
  curl -s -H "Authorization: Bearer abc123" "https://TARGET/admin"
