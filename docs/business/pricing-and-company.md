# Business Setup — Pricing, Stripe, Company

## 1. Pricing (current + validation plan)

| Plan | Price | Target buyer |
|---|---|---|
| Free | $0 | Individual dev / evaluation |
| Starter | $49/mo | Small team, 1–3 accounts, chasing SOC 2 |
| Pro | $299/mo | Growing multi-cloud org |
| Enterprise | Custom | MNC: SSO, scale, SLA |

**Validate before locking pricing:**
- [ ] Interview 10–15 ICP buyers; ask willingness-to-pay (Van Westendorp).
- [ ] Confirm the value metric (accounts? scans? findings?) matches how buyers think about scale.
- [ ] A/B the pricing page (Starter $49 vs $79); watch free→paid conversion.
- [ ] Add **annual billing (2 months free)** — improves cash flow & retention.
- [ ] Consider a 14-day Pro trial (the `seats`/`trialing` status already exist).

## 2. Stripe go-live checklist
- [ ] Create Stripe account; activate live mode (business details, bank).
- [ ] Create **Products** (Starter, Pro) and recurring **Prices**; copy the price IDs.
- [ ] Set env: `CSPM_BILLING_MODE=stripe`, `CSPM_STRIPE_SECRET_KEY`,
      `CSPM_STRIPE_PRICE_STARTER`, `CSPM_STRIPE_PRICE_PRO`.
- [ ] Add a webhook endpoint → `POST /api/v1/cspm/billing/webhook`; set
      `CSPM_STRIPE_WEBHOOK_SECRET`. Subscribe to `checkout.session.completed`,
      `customer.subscription.deleted`, `invoice.payment_failed`.
- [ ] Test with Stripe test cards end-to-end (checkout → plan flips → portal).
- [ ] Enable Stripe Tax if selling across regions; configure invoicing.
- [ ] Turn on Radar (fraud) and dunning (failed-payment retries).

> The code already implements Checkout, Billing Portal, and webhook sync — this
> is configuration + your Stripe account, which only you can provide.

## 3. Company & legal (needs you + a lawyer/accountant)
- [ ] Incorporate (e.g., US Delaware C-corp for fundraising, or LLC; or local
      equivalent). Get an EIN/company number and a business bank account.
- [ ] Publish **Terms** and **Privacy** (drafts in `web/legal/`) after legal review.
- [ ] Sign a **DPA** template for customers; maintain a sub-processor list.
- [ ] Trademark the brand name + logo (see `docs/brand/positioning.md`).
- [ ] Business insurance (tech E&O / cyber) — often required by enterprise buyers.

*These are real-world legal/financial acts and cannot be automated in code.*
