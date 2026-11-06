# Brute Force Attacks

## Overview

A brute force attack attempts to gain access to an account by repeatedly submitting authentication attempts, often using many passwords or credentials.

## Common Indicators

- Multiple failed login attempts
- Repeated authentication attempts against the same account
- High numbers of failures from a single source IP
- Successful authentication following repeated failures
- Multiple accounts targeted from the same source
- Unusual authentication frequency

## Investigation Guidance

When investigating suspected brute force activity:

1. Identify the source IP.
2. Identify the targeted username or accounts.
3. Review failed authentication events.
4. Check whether a successful login followed the failures.
5. Determine whether the source IP has known threat intelligence.
6. Map the behavior to MITRE ATT&CK where appropriate.

## Recommended Response

- Review the affected account.
- Check whether the account was successfully compromised.
- Investigate the source IP.
- Review authentication activity around the incident.
- Consider account protection measures such as password resets or MFA.
- Monitor the source for additional suspicious activity.

## MITRE ATT&CK

Brute force activity is associated with:

**T1110 — Brute Force**

Primary tactic:

**Credential Access**