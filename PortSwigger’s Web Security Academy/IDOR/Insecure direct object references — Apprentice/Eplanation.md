# User ID controlled by request parameter, with unpredictable user IDs — Practitioner

**Status:** Solved

---

## Goal

Exploit an IDOR vulnerability where user IDs are GUIDs (unpredictable). Find Carlos's GUID by discovering where it's leaked, then access his account.

---

## Steps (simple & complete)

1. **Log in to your account**
   - Use credentials (wiener:peter)
   - Go to "My account" and observe the URL:
```
   GET /my-account?id=4f8a9c2e-1b3d-4e7f-9a2c-8d1e3b5f7a9c
```
   - Notice it uses a GUID instead of a simple username

2. **Explore the application**
   - Browse around looking for places where user information is displayed
   - Check blog posts, comments, forums, or any public content
   - Look for author names or user profiles

3. **Find where GUIDs leak**
   - Click on a blog post or find any content by Carlos
   - Look for links to Carlos's profile or username references
   - Right-click → "View page source" (or use Burp)

4. **Extract Carlos's GUID**
   - In the HTML source, search for "carlos"
   - You'll find something like:
```html
   <a href="/blogs?userId=a1b2c3d4-e5f6-7890-abcd-ef1234567890">carlos</a>
```
   - Copy Carlos's GUID from the link

5. **Access Carlos's account**
   - Replace your GUID with Carlos's GUID in the my-account URL:
```bash
   curl -s "https://TARGET/my-account?id=a1b2c3d4-e5f6-7890-abcd-ef1234567890" \
     -H "Cookie: session=YOUR-SESSION-COOKIE"
```

6. **Retrieve the API key**
   - Carlos's account page will load
   - Find and copy his API key from the page

7. **Submit the solution**
   - Click "Submit solution"
   - Paste Carlos's API key to complete the lab

---

## Example

- Your account: `GET /my-account?id=4f8a9c2e-1b3d-4e7f-9a2c-8d1e3b5f7a9c`
- Carlos's GUID found in blog: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`
- IDOR exploit:
```bash
curl -s "https://TARGET/my-account?id=a1b2c3d4-e5f6-7890-abcd-ef1234567890" \
  -H "Cookie: session=your-session-here"
```

---

## Why this works

Using GUIDs instead of sequential IDs makes it harder to guess, but it doesn't fix the IDOR vulnerability. The real problem is that the application doesn't verify you have permission to view the requested account. Plus, GUIDs are often leaked in public areas like blog posts or API responses, making them discoverable. This is a perfect example of "security by obscurity" failing - hiding the ID format doesn't replace proper authorization checks.

---
