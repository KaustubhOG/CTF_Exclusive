# Authentication bypass via encryption oracle — Practitioner

**Status:** Solved

---

## Goal

Exploit encryption oracle to forge admin session cookie.

---

## Steps (simple & complete)

1. **Find encryption oracle**
   - Post invalid email in comment
   - Error cookie appears: `notification=Invalid%20email`
   - This cookie is encrypted!

2. **Decrypt session cookie**
   - Your session: `stay-logged-in=encrypted_value`
   - Encryption is same as notification cookie
   - We can decrypt by causing errors

3. **Craft admin cookie**
   - Goal: `stay-logged-in=administrator:timestamp`
   - Use notification parameter as oracle
   - Send: `notification=administrator:1234567890`
   - Copy encrypted value

4. **Replace session**
   - Delete your `stay-logged-in` cookie
   - Add new one with admin encrypted value
   - Access `/admin`
   - Delete carlos
   - Lab solved! ✓

---
