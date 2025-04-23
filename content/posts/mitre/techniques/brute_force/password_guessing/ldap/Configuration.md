---
title: Configuration
date: 2025-01-26
draft: false
author: Alex Jenkins
---
## Introduction
In this exercise I will be targeting LDAP, which is listed as one of the commonly targeted services in the Password Guessing techniques page on the MITRE ATT&CK framework. 
## Assumptions
1. Active Directory (AD) is installed and running, configured with a Domain Controller (DC).
2. Kali Linux is running and **connected to the same network** as the AD DC.
3. There are no firewall rules that will interfere with connection requests from Kali Linux to your AD server.
## Modify Password Policies
The very first step to this exercise is ensuring a user has been created. It may be necessary to change the default password policy in your AD server to ensure that a vulnerable password may be used. To do that open Group Policy Management Editor, navigate to *Computer Configuration/Policies/Windows Settings/Security Settings/Account Policies/Password Policy* and set the minimum password length to a low value - I've used a length of five. I also took the liberty of disabling the *Password must meet complexity requirements* policy. 

| Policy                                     | Setting      |
| ------------------------------------------ | ------------ |
| minimum password length                    | 5 characters |
| password must meet complexity requirements | disabled     |

## Create a new user
Next, open Active Directory Users and Computers. Locate your domain, right click the *Users* folder, and create a new user. For this exercise I'm going to be using a password from the rockyou wordlist, which is readily available in Kali Linux in */usr/share/wordlists* and just need to be extracted. You can do that with the *gunzip* command. I decided to use the 10th password in this list to simplify testing of blue team's patches. Once you've picked a password fill in the user details, uncheck "User must change password at next logon", and check "Password never expires". It should go without saying that in production environments this is not an ideal setup, but is much more convenient for our use-case. If you want to follow along, these are the credentials I used:

| Field                                   | Value  |
| --------------------------------------- | ------ |
| first name                              | scarab |
| user logon name                         | scarab |
| password                                | abc123 |
| user must change password at next logon | false  |
| password never expires                  | true   |
