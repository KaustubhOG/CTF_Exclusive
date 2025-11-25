# Insufficient workflow validation — Practitioner

**Status:** Solved

---

## Goal

Skip payment verification step in checkout workflow.

---

## Steps (simple & complete)

1. **Buy cheap item first**
   - Login: `wiener:peter`
   - Buy any cheap item ($10)
   - Observe checkout flow:
```
   /cart → /checkout → /checkout/confirm
```

2. **Add expensive item**
   - Add leather jacket ($1337) to cart
   - Don't click "Place order"

3. **Skip to confirmation**
   - Directly go to:
```
   GET /cart/checkout/confirm
```
   - Bypasses payment check!

4. **Order placed**
   - Lab solved! ✓

---
