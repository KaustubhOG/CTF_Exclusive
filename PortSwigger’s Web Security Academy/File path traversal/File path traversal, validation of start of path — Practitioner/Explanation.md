# File path traversal, validation of start of path — Practitioner

**Status:** Solved

---

## Goal

Bypass a filter that validates the path must start with an expected folder. Traverse from within that folder to reach sensitive files.

---

## Steps (simple & complete)

1. **Find the vulnerable endpoint**
   - Browse any product page and check how images load:
```
   GET /image?filename=12.jpg
```

2. **Test normal traversal**
   - Try basic traversal:
```bash
   curl -s "https://TARGET/image?filename=../../../etc/passwd"
```
   - This fails because the app validates the path must start with a specific folder.

3. **Understand the validation**
   - The app checks that the supplied path starts with the expected base folder (e.g., `/var/www/images/`)
   - If the path doesn't start with this folder, the request is blocked.

4. **Identify the base path**
   - From error messages or behavior, determine the expected base path
   - Usually something like: `/var/www/images/`

5. **Use path validation bypass**
   - Start with the required base path, then traverse out of it:
```bash
   curl -s "https://TARGET/image?filename=/var/www/images/../../../etc/passwd"
```

6. **How it works**
   - Validation check: path starts with `/var/www/images/` ✓ (passes)
   - File system resolution: `/var/www/images/../../../etc/passwd` → `/etc/passwd`
   - The traversal sequences work after validation passes.

7. **Verify success**
   - If you see the file contents, the bypass worked.

8. **Lab completion**
   - The lab automatically marks as solved when `/etc/passwd` is successfully retrieved.

---

## Example

- Vulnerable endpoint: `GET /image?filename=12.jpg`
- Working payload:
```bash
curl -s "https://TARGET/image?filename=/var/www/images/../../../etc/passwd"
```

---

**Lab 5 Complete ✓**