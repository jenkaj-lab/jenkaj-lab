---
title: DNS
date: 2025-06-11
draft: false
author: Alex Jenkins
---
| Category      | ID        | Description       |
| ------------- | --------- | ----------------- |
| Tactic        | TA011     | Command and Control |
| Technique     | T1071     | Application Layer Protocol  |
| Sub-Technique | T1071.004 | DNS |
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
(python script)

When running the script you should get output like below:
```
client @0x77042c1ca578 192.168.1.182#55499 (YWxleAo=.Ni4xNC4xMC1hcmNoMS0xCg==.homelab.local): query: YWxleAo=.Ni4xNC4xMC1hcmNoMS0xCg==.homelab.local IN TXT +E(0) (192.168.1.155)
```
