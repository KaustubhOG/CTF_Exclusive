# Inconsistent handling of exceptional input — Practitioner

**Status:** Solved

---

## Goal

Exploit email validation logic to register as admin user by using very long email addresses.

---

## Steps (simple & complete)

1. **Access email client**
   - Click "Email client" button
   - You get temp email like: `attacker@exploit-xyz.web-security-academy.net`

2. **Read lab description**
   - Admin users have email ending with `@dontwannacry.com`
   - Registration truncates long emails
   - We'll exploit this!

3. **Craft long email**
   - Create email that gets truncated to admin domain:
```
   very-long-string-here@dontwannacry.com.exploit-xyz.web-security-academy.net
```
   - Make the part before `@dontwannacry.com` exactly long enough so truncation cuts off everything after `.com`

4. **Calculate length**
   - Email field truncates at 255 chars
   - We need: `aaaa...@dontwannacry.com` (truncated)
   - Pad with 'a' characters before the @

5. **Register with long email**
```
   aaaaaaaaaa...aaaaaa@dontwannacry.com.exploit-xyz.web-security-academy.net
   (add ~200 'a' chars before @)
```

6. **Check your email**
   - Go back to email client
   - Click registration link
   - Account created!

7. **Login and access admin**
   - After email truncation, your recorded email is `...@dontwannacry.com`
   - Login with your credentials
   - Access admin panel
   - Delete carlos user
   - Lab solved! ✓

---

## Example

**Long email submitted:**
```
aaaaaaaaaaaa...aaaa@dontwannacry.com.exploit-abc.net
(200 a's)
```

**After truncation (255 chars):**
```
aaaaaaaaaaaa...aaaa@dontwannacry.com
```

System thinks your an admin! ✓

---

## Why it works

App truncates email but checks domain AFTER truncation - allows domain spoofing!

---

