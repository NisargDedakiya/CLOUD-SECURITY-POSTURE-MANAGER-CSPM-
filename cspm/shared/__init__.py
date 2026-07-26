"""Stubs for the shared platform backend that CSPM depends on.

Per the build spec (Section 2), CSPM is NOT standalone — auth, orgs, targets,
billing, audit log, and the reports/Claude endpoint already exist in the shared
backend. These stubs stand in for that foundation so CSPM can be developed and
tested in isolation, and are the seams where the real platform is wired in.
"""
