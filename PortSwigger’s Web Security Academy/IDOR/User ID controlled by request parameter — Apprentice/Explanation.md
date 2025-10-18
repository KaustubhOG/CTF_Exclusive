# User ID controlled by request parameter — Apprentice

**Status:** Solved

---

## Goal

Exploit a simple IDOR where the user ID is controlled by a request parameter. Access Carlos's account and retrieve his API key.

---

## Steps (simple & complete)

1. **Log in to your account**
   - Use the provided credentials (wiener:peter)
   - Navigate to "My account" page

2. **Observe the request**
   - Check the URL or intercept the request in Burp:
```
   GET /my-account?id=wiener
```
   - The `id` parameter directly controls whose account you're viewing
   - This is the vulnerable parameter

3. **Test the IDOR**
   - Simply change `wiener` to `carlos`:
```bash
   curl -s "https://TARGET/my-account?id=carlos" \
     -H "Cookie: session=YOUR-SESSION-COOKIE"
```

4. **Access Carlos's account**
   - The application doesn't check if you're authorized to view Carlos's account
   - You'll see Carlos's account page with his information

5. **Find the API key**
   - Look through Carlos's account page
   - The API key should be displayed clearly
   - Copy the entire API key string

6. **Submit the solution**
   - Click "Submit solution" button
   - Paste Carlos's API key
   - Lab solved!

---

## Example

- Your account: `GET /my-account?id=wiener`
- IDOR exploit:
```bash
curl -s "https://TARGET/my-account?id=carlos" \
  -H "Cookie: session=your-session-here"
```
- API key will be in the response body

---

## Why this works

This is the most basic form of IDOR. The application trusts whatever user ID you put in the `id` parameter without checking if your authenticated session actually has permission to view that user's data. It's like having a filing cabinet where anyone can ask for any file by number, and nobody checks if they're allowed to see it.

---

