# Configuration
## Server
1. Setup Ubuntu server - I'm using 24.04.2

### Domain Name System
Follow this guide: https://documentation.ubuntu.com/server/how-to/networking/install-dns/index.html
- Install bind9, dnsutils


## Infected Machine
On infected machine modify /etc/resolv.conf to include:
```
nameserver 192.168.1.155 # Change this to the IP of your DNS server
```
This simulates real-world DNS connection. In doing this you can keep it isolated to your private network, allowing the infected machine to treat your server as its own DNS - enabling IP resolution. In real-world scenarios this wouldn't be required because the domain would be recognised by a public DNS provider.
