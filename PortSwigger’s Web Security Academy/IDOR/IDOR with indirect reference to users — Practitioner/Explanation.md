# IDOR with indirect reference to users — Practitioner

**Status:** Solved

---

## Goal

Exploit an IDOR vulnerability where user references are indirect. Find a way to access Carlos's account and retrieve sensitive information.

---

## Steps (simple & complete)

1. **Understand the application**
   - Log in with your credentials (wiener:peter)
   - Navigate to "My account" section
   - Notice how the application handles user identification

2. **Analyze the redirect mechanism**
   - When you access "My account", check the request flow in Burp:
```
   GET /my-account
```
   - The app might redirect based on your session to:
```
   GET /my-account?id=wiener
```
   - Or it uses some indirect reference like a role or user parameter

3. **Look for indirect references**
   - Check if there's a parameter that references users indirectly
   - Common patterns include:
     - Username instead of ID
     - Role-based access (user, admin)
     - Sequential numbers mapped to usernames

4. **Test with Carlos's username**
   - Try replacing your username with `carlos`:
```bash
   curl -s "https://TARGET/my-account?id=carlos" \
     -H "Cookie: session=YOUR-SESSION-COOKIE"
```

5. **Bypass any redirects**
   - If the app tries to redirect you back, intercept in Burp
   - Change the `id` parameter before the redirect happens
   - Or follow the redirect manually with Carlos's username

6. **Retrieve Carlos's API key**
   - Once you access Carlos's account page, look for his API key
   - It should be displayed somewhere on the account page
   - Copy the API key

7. **Submit the solution**
   - Use the "Submit solution" button
   - Paste Carlos's API key to complete the lab

---

## Example

- Your account access: `GET /my-account?id=wiener`
- IDOR payload:
```bash
curl -s "https://TARGET/my-account?id=carlos" \
  -H "Cookie: session=your-session-here"
```
- Extract API key from the response

---

## Why this works

The application uses usernames as indirect object references but doesn't verify that your session actually belongs to the user whose account you're trying to access. Just because the reference is a username instead of a numeric ID doesn't make it secure - it's still an IDOR if there's no proper authorization check.

---

