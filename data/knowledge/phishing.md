# Phishing

## Overview

Phishing is a social engineering technique used to trick users into revealing credentials, executing malicious content, or interacting with attacker-controlled infrastructure.

## Common Indicators

- Suspicious email messages
- Unexpected links or attachments
- Lookalike domains
- Credential harvesting pages
- Urgent or unusual requests
- Links to unfamiliar external infrastructure

## Investigation Guidance

When investigating suspected phishing:

1. Extract URLs and domains from the message.
2. Check domain and IP reputation.
3. Inspect suspicious attachments when available.
4. Identify affected users.
5. Determine whether credentials were submitted.
6. Search for related authentication activity.
7. Correlate indicators with threat intelligence.

## Recommended Response

- Isolate affected endpoints when appropriate.
- Reset compromised credentials.
- Block confirmed malicious domains or IP addresses.
- Search for additional affected users.
- Review related authentication activity.
- Monitor for follow-on activity.

## MITRE ATT&CK

Phishing techniques are primarily associated with:

**TA0001 — Initial Access**