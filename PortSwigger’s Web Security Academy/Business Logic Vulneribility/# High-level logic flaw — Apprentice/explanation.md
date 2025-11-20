# High-level logic flaw — Apprentice

**Status:** Solved

---

## Goal

Exploit a logic flaw in the shopping cart to get items for free or negative prices.

---

## Steps (simple & complete)

1. **Login and explore**
   - Login: `wiener:peter`
   - You have $100 credit
   - Target: Lightweight jacket ($1337)

2. **Test negative quantities**
   - Add the expensive jacket to cart (quantity: 1)
   - Add a cheap item to cart
   - Go to cart page

3. **Intercept quantity update**
   - In cart, try changing quantity
   - Intercept the request in Burp:
```
   POST /cart
   productId=2&quantity=1
```

4. **Use negative quantity**
   - Change quantity to negative:
```
   productId=2&quantity=-10
```
   - This reduces your total price!

5. **Balance the prices**
   - Add expensive jacket (quantity: 1) = +$1337
   - Add cheap item (quantity: -50) = -$1337
   - Total: $0 or less

6. **Complete order**
   - Make total under $100
   - Place order
   - Lab solved! ✓

---

## Example

**Cart contents:**
```
Leather Jacket x1 = $1337
Cheap item x(-50) = -$1337
Total: $0
```

You got expensive jacket for free by using negative quantities!

---

## Why it works

App doesnt validate that quantity must be positive - classic logic flaw!

---

