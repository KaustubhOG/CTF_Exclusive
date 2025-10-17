# File path traversal, validation of file extension with null byte bypass — Practitioner

**Status:** Solved

---

## Goal

Bypass a filter that validates the filename must end with a specific file extension (like `.png`). Use null byte injection to bypass this check.

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
   - This fails because the app validates the filename must end with an image extension.

3. **Test with valid extension**
   - Try adding the extension:
```bash
   curl -s "https://TARGET/image?filename=../../../etc/passwd.png"
```
   - This still fails because the file doesn't actually exist with that extension.

4. **Understand the validation**
   - The app checks that the supplied filename ends with `.png` or similar extension
   - It performs a string check on the filename parameter.

5. **Use null byte injection**
   - In many programming languages, the null byte (`%00`) terminates a string
   - Add `%00` before the required extension:
```bash
   curl -s "https://TARGET/image?filename=../../../etc/passwd%00.png"
```

6. **How it works**
   - Validation check: sees `../../../etc/passwd%00.png` ends with `.png` ✓ (passes)
   - File system call: processes only up to `%00`, so it reads `../../../etc/passwd`
   - The `.png` part after null byte is ignored by the file system.

7. **Verify success**
   - If you see the file contents with usernames, the null byte bypass worked.

8. **Lab completion**
   - The lab automatically marks as solved when `/etc/passwd` is successfully retrieved.

---

## Example

- Vulnerable endpoint: `GET /image?filename=12.jpg`
- Working payload:
```bash
curl -s "https://TARGET/image?filename=../../../etc/passwd%00.png"
```

---

**Lab 6 Complete ✓**

