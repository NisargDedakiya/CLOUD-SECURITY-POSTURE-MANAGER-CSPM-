# Design-Partner Onboarding — Email Sequence

A 4-week lifecycle sequence to take a pilot from "connected" to "converted +
testimonial." Send from a real person (founder), plain text, short. Replace
`{…}` tokens. Pair with the in-app "Connect AWS" one-click flow
(`deploy/onboarding/`).

---

## 0 — Welcome / kickoff (immediately after they say yes)
**Subject:** You're in — let's connect {company}'s first AWS account
> Hi {name}, excited to have {company} as an Aegis design partner.
>
> Step 1 (2 min): connect one AWS account. It's **read-only** — you create a role
> we assume with a secret External ID; we never touch your resources.
> One-click setup: {launch_stack_link}
>
> Once it's connected, hit **Run scan** — you'll have findings within the hour.
> I'll follow up tomorrow to walk through them together. Reply here anytime.
> — {founder}

## 1 — Nudge if not connected (Day 2, only if no account)
**Subject:** Quick hand connecting {company}?
> Noticed the AWS account isn't linked yet — anything blocking you? Happy to hop
> on a 10-min call and do it together. The one-click role takes ~2 minutes:
> {launch_stack_link}

## 2 — First-value walkthrough (Day 2–3, after first scan)
**Subject:** Your top {N} cloud risks (and how to fix them)
> Great — first scan is in. Top items:
> 1. {finding_1} — {resource_1}
> 2. {finding_2} — {resource_2}
> 3. {finding_3} — {resource_3}
> Each has a copy-paste Terraform/CLI fix in the app (Findings → Details).
> Want me to walk through remediation on a quick call? Also: which compliance
> framework matters most to you right now — SOC 2, ISO, PCI?

## 3 — Compliance value (Day 5)
**Subject:** {company}'s SOC 2 evidence, one click
> You can now export auditor-ready evidence: Compliance → {framework} → Evidence.
> Your current score is {score}% ({passed}/{applicable} controls). Fixing the {n}
> open highs would take you to ~{projected}%. Want the export to share with your
> auditor?

## 4 — Turn on continuous monitoring (Week 2)
**Subject:** Get pinged the moment something drifts
> Point-in-time scans are good; continuous is better. Enable **Drift detection**
> + **Slack alerts** (Settings) so you hear immediately if a security group opens
> up or an S3 policy changes. Takes 2 minutes — want me to set it up with you?

## 5 — Mid-pilot check-in (Week 3)
**Subject:** How's Aegis landing for {company}?
> Quick pulse: you've fixed {fixed_count} issues and your score moved {x→y}. 🎉
> - What's most useful?
> - What's missing or annoying?
> - Anyone else on the team who should have access?
> Your feedback directly shapes what we build next.

## 6 — Convert (Week 4)
**Subject:** Keep Aegis running at {company}?
> The pilot wraps this week. Recap: {fixed_count} issues fixed, score {x→y},
> {frameworks} mapped. To keep monitoring after the pilot, the **Pro** plan
> ({price}/mo) covers your {accounts} accounts, all frameworks, drift, and
> integrations. Shall I switch you over?
> And — would you be open to a short quote / logo on our site? It helps a lot.

## 7 — Win-back (if they go quiet, Week 6)
**Subject:** Leave Aegis on for {company} (free 30 days)?
> No pressure — I'd hate for {company}'s posture to go unwatched. I can extend
> Pro free for 30 days so drift alerts keep running. Want me to flip it on?

---

### Tips
- Trigger emails off real product events (account connected, first scan, score
  change) rather than fixed dates where possible.
- Keep every email to one ask.
- Track: connect rate, time-to-first-finding, issues fixed, score delta,
  pilot→paid conversion, testimonial rate.
