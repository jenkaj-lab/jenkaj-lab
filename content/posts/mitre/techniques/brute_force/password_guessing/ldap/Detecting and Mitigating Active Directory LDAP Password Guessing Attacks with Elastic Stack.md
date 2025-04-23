---
title: Detecting and Mitigating Active Directory LDAP Password Guessing Attacks with Elastic Stack
date: 2025-01-26
draft: false
author: Alex Jenkins
---
# Blue Team
## Assumptions
1. ELK is already setup and ingesting audit logs from the AD server

## Detection
Able to look through the logs to see failures with bad passwords.
![[ldap_brute_force_result.png]]

- Monitor for many failed authentication attempts

## Mitigation
### Account Use Policies
- Account lockout (can be bad, creating a sort of DoS if policies are too strict with all accounts targeted in the brute force being locked out)
- Conditional access to block untrusted/unmanaged/non-compliant devices or from outside defined IP range

### Multi-Factor Authentication
Multi-Factor Authentication (MFA) is one of the best options for validating a login. 
- show how

### Password Policies
Yes, the things that we disabled. These can be re-applied to add a stronger layer of protection to password guessing attacks.

Refer to NIST guidelines