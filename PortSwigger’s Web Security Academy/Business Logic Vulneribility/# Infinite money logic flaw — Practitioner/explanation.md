# Infinite money logic flaw — Practitioner

**Status:** Solved

---

## Goal

Exploit gift card system to generate infinite money.

---

## Steps (simple & complete)

1. **Understand the system**
   - Gift cards cost $10
   - Signup gives 30% discount code
   - Gift cards worth $10 can be redeemed

2. **The exploit**
   - Buy gift card for $10
   - Apply 30% coupon → pay $7
   - Redeem card → get $10 credit
   - Profit: $3 per cycle!

3. **Automate with macro**
   - In Burp, create macro:
     1. Add gift card to cart
     2. Apply coupon
     3. Complete purchase
     4. Redeem gift card code
   - Run macro 400+ times

4. **Buy expensive item**
   - After macro, you have $1000+ credit
   - Buy leather jacket
   - Lab solved! ✓

---