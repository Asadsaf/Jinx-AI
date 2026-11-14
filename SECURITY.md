# Security Policy

Jinx is an **offensive-security testing tool**. It exists to help defenders find real
flaws in AI agents before attackers do. Please use it accordingly.

## Authorized use only

Run Jinx only against:

- systems **you own**, or
- systems you have **explicit, written authorization** to test, or
- a published bug-bounty / vulnerability-disclosure program that grants **safe harbor**.

Testing someone else's AI agent without authorization may be illegal in your jurisdiction.
Every non-mock `jinx run` asks you to confirm authorization before it sends a single probe.
You are responsible for how you use this tool.

## Reporting a vulnerability

### In a target you tested with Jinx
A finding against a vendor's agent belongs to **that vendor**. Report it through their
security contact or bug-bounty program, following their disclosure timeline — not here.

### In Jinx itself
If you find a security issue in Jinx's own code (for example, a way the tool could leak the
operator's data, or run commands it shouldn't), please **do not open a public issue**.
Open a private report via GitHub Security Advisories:

> **Security → Report a vulnerability** on this repository.

Include the version (`jinx info`), reproduction steps, and impact. You'll get an
acknowledgement, and a fix or an explanation of why it isn't one.

## Supported versions

Jinx is pre-1.0; only the latest `main` is supported. Pin a commit if you need stability.
