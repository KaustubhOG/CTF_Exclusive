

# Authentication bypass via flawed state machine — Practitioner

**Status:** Solved

---

## Goal

Exploit state machine flaw during login to skip role selection.

---

## Steps (simple & complete)

1. **Observe normal login**
   - Login: `wiener:peter`
   - After login → redirects to `/role-selector`
   - Must select role (user/admin blocked)

2. **Intercept role selection**
   - Login again
   - After POST to `/login`, drop the redirect to `/role-selector`
   - In Burp: Intercept → Drop request

3. **Access without role**
   - Go directly to `/admin`
   - You have admin access!
   - Delete carlos
   - Lab solved! ✓

---

**Lab 8 Complete ✓**