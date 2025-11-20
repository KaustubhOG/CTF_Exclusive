# Low-level logic flaw — Practitioner

**Status:** Solved

---

## Goal

Exploit integer overflow in cart total calculation to purchase expensive items.

---

## Steps (simple & complete)

1. **Login and analyze**
   - Login: `wiener:peter`
   - You have $100 credit
   - Target: Leather jacket ($1337)

2. **Find a cheap item**
   - Look for cheapest item in store
   - Example: "Sticker" for $0.57

3. **Test cart limits**
   - Add many items to cart
   - Keep adding until total is very large
   - Try to overflow the integer!

4. **Cause integer overflow**
   - Add cheap item 1000+ times
   - Total reaches max integer value
   - Then wraps around to negative!
   - Use Burp Intruder to automate

5. **Setup Burp Intruder**
```
   POST /cart
   productId=1&quantity=99
```
   - Send to Intruder
   - Set payload: Numbers 1-500
   - Run attack to add items quickly

6. **Monitor cart total**
   - Total goes: $100 → $10,000 → $214,748,3647 → -$214,748,3648
   - When it goes negative, stop!

7. **Balance to target price**
   - Add/remove items to get total near $0
   - Make sure its under $100
   - Add your expensive jacket
   - Place order ✓

---

## Example

**Cart after overflow:**
```
Sticker x 9999 = -$5000 (overflowed!)
Jacket x 1 = $1337
Total: -$3663 (negative price!)
```

Add more items until total is between $0-$100, then checkout!

---

## Why it works

Cart uses 32-bit integer - max value ~2.1 billion. When exceeded, it wraps to negative!

---

