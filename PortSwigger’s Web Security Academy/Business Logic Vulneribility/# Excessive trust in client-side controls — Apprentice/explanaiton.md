# Excessive trust in client-side controls — Apprentice


---

## Goal

Bypass client-side price controls to purchase expensive items for cheap.

---

## Steps (simple & complete)

1. **Browse the shop**
   - Login with: `wiener:peter`
   - Find expensive item like "Lightweight l33t leather jacket" ($1337)
   - You only have $100 credit

2. **Add to cart normally**
   - Click "Add to cart"
   - Intercept request in Burp Suite

3. **Observe the price parameter**
   - Request looks like:
```
   POST /cart
   productId=1&quantity=1&price=133700
```
   - Price is sent from client! Thats the bug

4. **Modify the price**
   - Change price to something you can afford:
```
   productId=1&quantity=1&price=1
```
   - Forward the request

5. **Complete purchase**
   - Go to cart
   - Item shows $0.01 price!
   - Click "Place order"
   - Lab solved ✓

---

## Example

**Original request:**
```
price=133700
```

**Modified request:**
```
price=1
```

You bought $1337 jacket for $0.01! 

---

## Why this happens

Developer trusted client to send correct price - big mistake! Never trust client-side data for critical values.

---

