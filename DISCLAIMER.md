# Authorized Use Only

Desisherlock is a reconnaissance, vulnerability-assessment, and reporting
toolkit intended **solely** for security professionals conducting
authorized testing, and for educational use in controlled environments
(labs, CTFs, your own infrastructure).

By using this tool you agree that:

- You have **explicit, documented authorization** to scan, probe, or query
  every target you point Desisherlock at.
- You are solely responsible for complying with all applicable laws,
  regulations, and contractual terms (including any rules of engagement)
  in your jurisdiction and the target's.
- The authors and contributors accept no liability for misuse, damage, or
  legal consequences arising from use of this software.

## What this tool deliberately does NOT do

Desisherlock is scoped to recon, assessment, and reporting only. It does
**not** include, and will not accept contributions that add:

- Exploit modules or proof-of-concept exploitation code
- Payload or shellcode generators
- Credential brute-forcers or password-spraying tools against live
  services
- Any capability whose purpose is to gain unauthorized access to a
  system, rather than to tell you whether it *might* be vulnerable

Port scanning, CVE/CVSS lookup, HTTP header/misconfiguration checks, TLS
inspection, DNS enumeration, hash *identification* (not cracking), and
WHOIS lookups are all in scope because they answer "is this exposed /
outdated / misconfigured?" without ever attempting to breach anything.

If you need exploitation tooling, that is a different class of tool with
different legal and ethical obligations - use something purpose-built for
that (in an authorized engagement) instead.
