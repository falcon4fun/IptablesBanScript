# IptablesBanScript

### Annoyed by freaking thousands RDP, SSH and other services brute force?
### Annoyed by specific port scanners?
### Annoyed by bots which floods with connections to specific services?

You can try my this project. 

This was written on FreshTomato 2021.2 working on Netgear R6400. Those rules WILL need some modifications on other router firmwares or distributive because some rules are inserted on specified position.
Previously I've used only recent module and found it ineffective. Some IPs come again after temp ban after few hours/days.
The better way is to use IPSet sets to ban IPs completely. IPSet cause very small resource overhead minimizing count of iptables ban rules.
Moreover, Brute force rate from one IP can be 20 hits per 2 hours because of many proxies/IPs available

### Prerequisites:
1. Iptables (tested on v1.8.7)
2. IPset (tested on v6.38)
3. Loaded modules: ip_set, xt_set, ip_set_hash_ip
4. xt_recent (or maybe ipt_recent) working
5. Some understanding how iptables works at all (I will try to give some theory in ELI5 method below)

You can check modules:
1) if they exist on your FW by running `modprobe -l | grep "ip_\|xt_set" | sort`
2) if they are already loaded `lsmod | grep "ip_\|xt_set" | sort`

Some theory (scroll down if you understand):
Let's imagine we have a router in this case with NAT. Iptables has 3 main chains: input, forward and output.
1. If the external client sends the packet to router, the packet goes in Input chain
2. If the external client sends a packet to somewhere inside NAT (machine behind the router), the packet hits in the Forward chain. Forward chain works with input and output packets of NATted clients
3. If our computer behind router sends a packet, the packet hits Output chain
Quite an easy? So, we need to work with Input and Forward chains for this task.

Tomato firmware have some rules by default with some my open ports. As an example:
```
iptables -L -n -v --line-numbers
Chain INPUT (policy DROP 64 packets, 4258 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 ACCEPT     all  --  tun21  *       0.0.0.0/0            0.0.0.0/0
2        0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:1194
3        1    56 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            state INVALID
4       75 12627 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
5       22  4374 ACCEPT     all  --  lo     *       0.0.0.0/0            0.0.0.0/0
6       21  2292 ACCEPT     all  --  br0    *       0.0.0.0/0            0.0.0.0/0
7        0     0 ACCEPT     icmp --  *      *       0.0.0.0/0            0.0.0.0/0            icmptype 8 state NEW,RELATED,ESTABLISHED
8        0     0 ACCEPT     icmp --  *      *       0.0.0.0/0            0.0.0.0/0            icmptype 30 state NEW,RELATED,ESTABLISHED
9        0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpts:33434:33534
10       0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:22

Chain FORWARD (policy DROP 0 packets, 0 bytes)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 ACCEPT     all  --  tun21  *       0.0.0.0/0            0.0.0.0/0
2       41  1904 ACCEPT     all  --  br0    br0     0.0.0.0/0            0.0.0.0/0
3        0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            state INVALID
4      248 34013 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED
5       47  4869 wanin      all  --  vlan2  *       0.0.0.0/0            0.0.0.0/0
6      166 17627 wanout     all  --  *      vlan2   0.0.0.0/0            0.0.0.0/0
7      166 17627 ACCEPT     all  --  br0    *       0.0.0.0/0            0.0.0.0/0
8        0     0 upnp       all  --  vlan2  *       0.0.0.0/0            0.0.0.0/0

Chain OUTPUT (policy ACCEPT 5 packets, 384 bytes)
num   pkts bytes target     prot opt in     out     source               destination

Chain logdrop (0 references)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 LOG        all  --  *      *       0.0.0.0/0            0.0.0.0/0            state NEW LOG flags 39 level 4 prefix "DROP "
2        0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0

Chain logreject (0 references)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 LOG        all  --  *      *       0.0.0.0/0            0.0.0.0/0            LOG flags 39 level 4 prefix "REJECT "
2        0     0 REJECT     tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            reject-with tcp-reset

Chain upnp (1 references)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            192.168.0.100        udp dpt:53030

Chain wanin (1 references)
num   pkts bytes target     prot opt in     out     source               destination
1        0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            192.168.0.101        tcp dpt:990
2        0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            192.168.0.101        tcp dpt:21
3       0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            192.168.0.100        tcp dpt:3389
4       0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            192.168.0.100        udp dpt:3389
5       0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            192.168.0.101        tcp dpt:3399
6       0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            192.168.0.101        udp dpt:3399
7       0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            192.168.0.100        udp dpt:27100
8       9   472 ACCEPT     tcp  --  *      *       0.0.0.0/0            192.168.0.100        tcp dpt:54321
9      38  4397 ACCEPT     udp  --  *      *       0.0.0.0/0            192.168.0.100        udp dpt:54321
10       0     0 ACCEPT     tcp  --  *      *       0.0.0.0/0            192.168.0.110        tcp dpt:54323
11       0     0 ACCEPT     udp  --  *      *       0.0.0.0/0            192.168.0.110        udp dpt:54323

Chain wanout (1 references)
num   pkts bytes target     prot opt in     out     source               destination
```

Every packet is checked step by step from num #1 to num #XX of corresponding chain. 
If the packet matches any rule, it does its "Target".
If the target is another chain, it steps in that chain and go step by step from num #1 to num #xx and exists if there is no accept, drop, reject target. Those "targets" does action and forgets about the packet.


We need to create some new filtering chains and redirect from Input and Forward chains to them. 
They should be after 6 line in Input chain and before Forward 5 line or inside Wanin chain because we have a rule for inbound forwarded traffic.
We don't want to filter outbound traffic so let's filter inside Wanin chain. Alternatively you can modify my rules with "-i" parameter with interface name to filter from wan->lan

We have:
1. Globally opened ssh on 22 TCP port on our router (i.e. we need to access our router from somewhere)
2. RDP TCP/UDP ports for clients (behind the Nat) on 3389 and 3389
3. Event log shows many audit events with failed logon from remote machines (ID 4625 for example) who tries to brute force login:pass
4. Ssh log is full of the same

In my opinion, the router can and should work on it.
Main logic of my rules:
1. Create IPSet some tables (Will call them SETs to not confuse with Iptables TABLES) with timeouts where to store timed, global and flood ban.
In current example we need SSHPorts, RDPPorts, GlobalBan, FloodBan to be created.
2. We will check if IP is inside IPSet SET. If true, we reject connection with tcp-reset
3. We need to create some chains where to jump in. Let them be with the same name: SSHPorts, RDPPorts, GlobalBan, FloodBan
4. Now we need to check if packets is matches rule with destination port (22 or 3389 or 3399) it will go to corresponding chain. Example: we have 3389 port and Rapports chain.
5. Next we will check if IP appears to be flooder one
6. We send him to FloodBan chain
7. FloodBan chain adds every IP to xt_recent list called "FloodRecent" with timestamp and counter
8. Next it checks if there was more than 60 NEW connections in the last 120 seconds. If True, we add that IP to FloodBan SET (ban it. WHY YOU BULLY ME U FREAKIN BEACH)
9. If this IP is banned, we should clean xt_recent entry (optimization. Why should we store and track them?)
10. If this IP is banned, Reject this connection
11. If 7-10 are false, we step out from FloodBan chain to our RDPPorts chain
12. RDPPorts chain add every IP to xt_recent list called "RDPRecent" with timestamp and counter
13. Next it checks if there was more than 5 NEW connections in the last 60 seconds. If true, add IP to RDPPorts SET.
Why should IP create NEW connections 5 times per minute? Maybe because Windows disconnected it?
RDPPorts SET is a timeout one. It has 300s timeout (or any other value). IP will be removed from that SET after timeout.
So we ban IP for 300s. But RECENT module (12 paragraph) will still count temporary banned IP and log timestamps and increment counter. Brute force software likes reconnecting many and many times. Any real person will not do that after service unavailable if he knows how his time lock works.
14. Another rule: if there was more than 10 NEW connections in the last 7200 seconds (2 hours), add IP to GlobalBan SET.
So if IP keeps creating NEW connections, it should be banned forever. Don't forget to tweak values if you or your workers like reconnecting to machines. In my case, I need RDP, SSH and other services not more than 5-10 times per last 2 hours. Ordinary, I'm not reconnecting to them. I keep RDP and other sessions alive.
15. If there was more than 15 NEW connections in 21600 seconds (6 hours), add IP to GlobalBan SET. Like 14 paragraphs: We ban >15 connections per last 6 hours, we ban them.
16. If this IP is globally banned, we should clean xt_recent entry. Optimization again
17. If this IP is banned either temporary or globally, we reject this connection

The whole example should look like:
```bash
#!/bin/sh

#Portlists to generate rules
RDPPorts="3389 3399"
SSHPorts="22"

#Static piece of command
iptablesPart1="-p tcp -m state --state NEW"

#Creating SETs (1 paragraph)
ipset -exist create RDPPorts hash:ip family inet timeout 300
ipset -exist create SSHPorts hash:ip family inet timeout 120
ipset -exist create GlobalBan hash:ip
ipset -exist create FloodBan hash:ip

#We add them in REVERSE ORDER! (2 paragraph)
iptables -w 5 -I INPUT 7 -m set --match-set FloodBan src -j REJECT --reject-with icmp-port-unreachable
iptables -w 5 -I INPUT 7 -p tcp -m set --match-set FloodBan src -j REJECT --reject-with tcp-reset
iptables -w 5 -I INPUT 7 -m set --match-set GlobalBan src -j REJECT --reject-with icmp-port-unreachable
iptables -w 5 -I INPUT 7 -p tcp -m set --match-set GlobalBan src -j REJECT --reject-with tcp-reset

#And they are REVERSED too! (2)
iptables -w 5 -I wanin 1 -m set --match-set FloodBan src -j REJECT --reject-with icmp-port-unreachable
iptables -w 5 -I wanin 1 -p tcp -m set --match-set FloodBan src -j REJECT --reject-with tcp-reset
iptables -w 5 -I wanin 1 -m set --match-set GlobalBan src -j REJECT --reject-with icmp-port-unreachable
iptables -w 5 -I wanin 1 -p tcp -m set --match-set GlobalBan src -j REJECT --reject-with tcp-reset

#Create Chains (3)
iptables -w 5 -N FloodBan
iptables -w 5 -N RDPPorts
iptables -w 5 -N SSHPorts

#FloodBan chain. (7-11)
iptables -w 5 -A FloodBan -m conntrack --ctstate NEW -m recent --set --name FloodRecent
iptables -w 5 -A FloodBan -m conntrack --ctstate NEW -m recent --rcheck --seconds 120 --hitcount 60 --name FloodRecent -j SET --add-set FloodBan src
iptables -w 5 -A FloodBan -m set --match-set FloodBan src -m recent --name FloodRecent --remove
iptables -w 5 -A FloodBan -p tcp -m set --match-set FloodBan src -j REJECT --reject-with tcp-reset
iptables -w 5 -A FloodBan -m set --match-set FloodBan src -j REJECT --reject-with icmp-port-unreachable

#RDPPorts chain. (4, 12-17)
iptables -w 5 -A RDPPorts -j FloodBan
iptables -w 5 -A RDPPorts -m conntrack --ctstate NEW -m recent --set --name RDPRecent
iptables -w 5 -A RDPPorts -m conntrack --ctstate NEW -m recent --rcheck --seconds 60 --hitcount 5 --name RDPRecent -j SET --add-set RDPPorts src
iptables -w 5 -A RDPPorts -m conntrack --ctstate NEW -m recent --rcheck --seconds 7200 --hitcount 10 --name RDPRecent -j SET --add-set GlobalBan src
iptables -w 5 -A RDPPorts -m conntrack --ctstate NEW -m recent --rcheck --seconds 21600 --hitcount 15 --name RDPRecent -j SET --add-set GlobalBan src
iptables -w 5 -A RDPPorts -m set --match-set GlobalBan src -m recent --name RDPRecent --remove
iptables -w 5 -A RDPPorts -p tcp -m set --match-set RDPPorts src -j REJECT --reject-with tcp-reset
iptables -w 5 -A RDPPorts -m set --match-set RDPPorts src -j REJECT --reject-with icmp-port-unreachable

iptables -w 5 -A SSHPorts -j FloodBan
iptables -w 5 -A SSHPorts -m conntrack --ctstate NEW -m recent --set --name SSHRecent
iptables -w 5 -A SSHPorts -m conntrack --ctstate NEW -m recent --rcheck --seconds 60 --hitcount 5 --name SSHRecent -j SET --add-set SSHPorts src
iptables -w 5 -A SSHPorts -m conntrack --ctstate NEW -m recent --rcheck --seconds 3600 --hitcount 10 --name SSHRecent -j SET --add-set GlobalBan src
iptables -w 5 -A SSHPorts -m conntrack --ctstate NEW -m recent --rcheck --seconds 21600 --hitcount 15 --name SSHRecent -j SET --add-set GlobalBan src
iptables -w 5 -A SSHPorts -m set --match-set GlobalBan src -m recent --name SSHRecent --remove
iptables -w 5 -A SSHPorts -p tcp -m set --match-set SSHPorts src -j REJECT --reject-with tcp-reset
iptables -w 5 -A SSHPorts -m set --match-set SSHPorts src -j REJECT --reject-with icmp-port-unreachable

#Generate rules (4 paragraph)
for port in $RDPPorts; do
    iptables -w 5 -I INPUT 11 $iptablesPart1 --dport $port -j RDPPorts
    iptables -w 5 -I wanin 5 $iptablesPart1 --dport $port -j RDPPorts
done

for port in $SSHPorts; do
    iptables -w 5 -I INPUT 11 $iptablesPart1 --dport $port -j SSHPorts
done

#Loading SETs from saved ones
ipset -exist restore < /opt/root/customFW/ipset.list
```
