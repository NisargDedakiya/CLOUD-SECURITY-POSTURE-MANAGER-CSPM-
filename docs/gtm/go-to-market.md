# Go-To-Market — Pilot Plan, Pitch, Outreach

## 1. Design-partner pilot (first 3–5 customers)

**Goal:** prove Aegis finds real, actionable issues in real accounts and produces
a compliance report a buyer values. Free during pilot in exchange for feedback +
a logo/quote if they're happy.

**Ideal design partners:** startups on AWS, 10–100 engineers, actively pursuing
SOC 2, with a named security owner.

**Pilot flow (4 weeks):**
1. **Week 0 — onboard:** they create the read-only role; connect 1 AWS account;
   first scan. Success = findings within 30 minutes.
2. **Week 1 — value:** walk through top findings + remediation; export a SOC 2
   evidence report. Success = they fix ≥3 issues.
3. **Weeks 2–3 — habit:** enable drift + Slack alerts; weekly check-in.
4. **Week 4 — convert:** review posture-score improvement; ask for the paid plan
   + a testimonial + referral.

**What to measure:** time-to-first-finding, # findings fixed, posture-score delta,
weekly active usage, "would you pay?" (and how much).

## 2. One-pager (sales sheet)

> **Aegis — Cloud security posture, on autopilot.**
> Continuously audit AWS/GCP/Azure against CIS, SOC 2, ISO 27001 and PCI DSS.
> Find misconfigurations before attackers do; export auditor-ready evidence.
>
> - **Continuous, not point-in-time** — drift detection catches risky changes fast.
> - **Compliance-mapped** — per-framework scores + one-click evidence.
> - **Read-only & safe** — least-privilege, never modifies your cloud.
> - **Starts free** — upgrade when you scale. No six-figure contract.
>
> *Set up in minutes. First findings in under an hour.*

## 3. Outreach templates

**Cold email (to a Head of Security / CTO):**
> Subject: SOC 2 evidence without the spreadsheet grind?
>
> Hi {name} — saw {company} is {hiring security / SOC 2 / scaling on AWS}.
> Teams your size usually collect cloud-compliance evidence by hand. Aegis scans
> your AWS/GCP/Azure continuously, maps every finding to SOC 2/CIS, and exports
> auditor-ready evidence — read-only, set up in minutes.
> Open to a 20-min pilot? First findings within the hour. — {you}

**Founder-led LinkedIn DM:**
> Building Aegis (continuous cloud posture + compliance, self-serve pricing).
> Looking for 3 design partners on AWS chasing SOC 2 — free during the pilot for
> feedback. Worth a quick look?

**Post-pilot ask:**
> You fixed {N} issues and your CIS score went {x→y}. Would {company} move to the
> Pro plan? And could I quote you / use your logo?

## 4. Channels to test
- Founder-led outbound to ICP (above).
- Content: "SOC 2 for startups on AWS" checklist; publish the check catalog.
- OSS/community: since we ingest Prowler, engage that community.
- Partnerships: vCISO / compliance consultants who resell.
