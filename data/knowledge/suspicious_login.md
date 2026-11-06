# Suspicious Login Activity

## Overview

Suspicious login activity occurs when authentication behavior deviates from expected patterns or contains indicators associated with account compromise.

## Common Indicators

- Failed logins followed by a successful login
- Successful login from an unusual source IP
- Authentication outside normal working hours
- Multiple authentication attempts within a short period
- Unexpected geographic or network origin
- Repeated access attempts against privileged accounts

## Investigation Guidance

When investigating suspicious authentication:

1. Identify the username.
2. Identify the source IP.
3. Review authentication events chronologically.
4. Look for failed attempts preceding successful authentication.
5. Determine whether the account is privileged.
6. Correlate the activity with threat intelligence.
7. Review related endpoint or network activity when available.

## Recommended Response

- Verify whether the successful login was legitimate.
- Review the affected account.
- Check for additional suspicious activity.
- Consider credential rotation if compromise is suspected.
- Monitor subsequent authentication attempts.

## Analyst Consideration

A successful login does not automatically indicate compromise. The surrounding authentication context and supporting evidence should be evaluated before reaching a conclusion.