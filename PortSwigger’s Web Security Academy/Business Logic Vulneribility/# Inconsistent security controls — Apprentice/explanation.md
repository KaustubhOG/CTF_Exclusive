# Inconsistent security controls — Apprentice

**Status:** Solved

---

## Goal

Register account, then change email to admin domain to access admin panel.

---

## Steps (simple & complete)

1. **Use email client**
   - Click "Email client" 
   - Get temp email: `attacker@exploit-xyz.net`

2. **Register account**
   - Register with your email
   - Verify via email link

3. **Login and change email**
   - Login to your account
   - Go to "My account"
   - Update email to: `anything@dontwannacry.com`
   - No verification needed for email change!

4. **Access admin panel**
   - Refresh page
   - Admin panel appears
   - Delete carlos
   - Lab solved! ✓

---

## Example

**Initial email:** `test@exploit-xyz.net`  
**Changed to:** `admin@dontwannacry.com`  
Result: Admin access granted!

---

