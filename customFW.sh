#!/bin/sh

#Ports list
RDPPorts1="3388 3389 3399"
HoneyPorts1="1024 8291 8728"
HoneyPorts2="3377 3378 3379 3380 3381 3382 3383 3384 3385 3386 3387 3390 3391 3392 3392 3393 3394 3395 3396 3397 3398"
SSHPorts="22 23"
VPNPorts="1194 1723"
FTPPorts="21 990"
ProxyPorts="3773 9875"

iptablesPart1="-p tcp -m state --state NEW"

#Init IPSet SETs
ipset -exist create RDPPorts1 hash:ip family inet timeout 300
ipset -exist create HoneyPorts1 hash:ip family inet timeout 600
ipset -exist create HoneyPorts2 hash:ip family inet timeout 600
ipset -exist create SSHPorts hash:ip family inet timeout 120
ipset -exist create VPNPorts hash:ip family inet timeout 120
ipset -exist create FTPPorts hash:ip family inet timeout 300
ipset -exist create ProxyPorts hash:ip family inet timeout 300
ipset -exist create GlobalBan hash:ip
ipset -exist create FloodBan hash:ip

#We should reject both TCP and UDP packets from attackers
#Reject input rules (should be smwhere on top). Invert order insert. Last will be first and first will be last after inserting them 
iptables -w 5 -I INPUT 7 -m set --match-set FloodBan src -j REJECT --reject-with icmp-port-unreachable
iptables -w 5 -I INPUT 7 -p tcp -m set --match-set FloodBan src -j REJECT --reject-with tcp-reset
iptables -w 5 -I INPUT 7 -m set --match-set GlobalBan src -j REJECT --reject-with icmp-port-unreachable
iptables -w 5 -I INPUT 7 -p tcp -m set --match-set GlobalBan src -j REJECT --reject-with tcp-reset

#Reject wanin rules (should be smwhere on top)
iptables -w 5 -I wanin 1 -m set --match-set FloodBan src -j REJECT --reject-with icmp-port-unreachable
iptables -w 5 -I wanin 1 -p tcp -m set --match-set FloodBan src -j REJECT --reject-with tcp-reset
iptables -w 5 -I wanin 1 -m set --match-set GlobalBan src -j REJECT --reject-with icmp-port-unreachable
iptables -w 5 -I wanin 1 -p tcp -m set --match-set GlobalBan src -j REJECT --reject-with tcp-reset

#Create chains
iptables -w 5 -N FloodBan
iptables -w 5 -N RDPPorts1
iptables -w 5 -N SSHPorts
iptables -w 5 -N VPNPorts
iptables -w 5 -N FTPPorts
iptables -w 5 -N ProxyPorts
iptables -w 5 -N HoneyPorts1
iptables -w 5 -N HoneyPorts2

#Flood protection 60 packets per 120s. Count them from FloodRecent xt_recent
#If > that 60p/120s then remove from FloodRecent (why should we store them after ban?) and push to FloodBan SET
iptables -w 5 -A FloodBan -m conntrack --ctstate NEW -m recent --set --name FloodRecent
iptables -w 5 -A FloodBan -m conntrack --ctstate NEW -m recent --rcheck --seconds 120 --hitcount 60 --name FloodRecent -j SET --add-set FloodBan src
iptables -w 5 -A FloodBan -m set --match-set FloodBan src -m recent --name FloodRecent --remove
iptables -w 5 -A FloodBan -p tcp -m set --match-set FloodBan src -j REJECT --reject-with tcp-reset
iptables -w 5 -A FloodBan -m set --match-set FloodBan src -j REJECT --reject-with icmp-port-unreachable


#Dont know how to make better logic. If connection hits 120, it will be banned but after next iteration. 
#100 time will accept the connection because of removing entry from RDPRecent. REJECT rule will not trigger
#I dont want to add more rules with adding GlobalBan with RDPPorts1 too. I think it can live with 100+1 iterations. Nobody cares that +-1
#I really dont want to store inside recent tables that is already banned in ipset 

#Test rule. Just in case. The LAN rules should be BEFORE jump to these chains! So we don't need to return from here if source adress is lan.
#iptables -w 5 -A RDPPorts1 -s 192.168.0.0/22 -j RETURN
iptables -w 5 -A RDPPorts1 -j FloodBan
iptables -w 5 -A RDPPorts1 -m conntrack --ctstate NEW -m recent --set --name RDPRecent
iptables -w 5 -A RDPPorts1 -m conntrack --ctstate NEW -m recent --rcheck --seconds 60 --hitcount 5 --name RDPRecent -j SET --add-set RDPPorts1 src
iptables -w 5 -A RDPPorts1 -m conntrack --ctstate NEW -m recent --rcheck --seconds 7200 --hitcount 10 --name RDPRecent -j SET --add-set GlobalBan src
iptables -w 5 -A RDPPorts1 -m conntrack --ctstate NEW -m recent --rcheck --seconds 21600 --hitcount 15 --name RDPRecent -j SET --add-set GlobalBan src
iptables -w 5 -A RDPPorts1 -m set --match-set GlobalBan src -m recent --name RDPRecent --remove
iptables -w 5 -A RDPPorts1 -p tcp -m set --match-set RDPPorts1 src -j REJECT --reject-with tcp-reset
iptables -w 5 -A RDPPorts1 -m set --match-set RDPPorts1 src -j REJECT --reject-with icmp-port-unreachable

#Test rule. Just in case
#iptables -w 5 -A SSHPorts -s 192.168.0.0/22 -j RETURN
iptables -w 5 -A SSHPorts -j FloodBan
iptables -w 5 -A SSHPorts -m conntrack --ctstate NEW -m recent --set --name SSHRecent
iptables -w 5 -A SSHPorts -m conntrack --ctstate NEW -m recent --rcheck --seconds 60 --hitcount 5 --name SSHRecent -j SET --add-set SSHPorts src
iptables -w 5 -A SSHPorts -m conntrack --ctstate NEW -m recent --rcheck --seconds 3600 --hitcount 10 --name SSHRecent -j SET --add-set GlobalBan src
iptables -w 5 -A SSHPorts -m conntrack --ctstate NEW -m recent --rcheck --seconds 21600 --hitcount 15 --name SSHRecent -j SET --add-set GlobalBan src
iptables -w 5 -A SSHPorts -m set --match-set GlobalBan src -m recent --name SSHRecent --remove
iptables -w 5 -A SSHPorts -p tcp -m set --match-set SSHPorts src -j REJECT --reject-with tcp-reset
iptables -w 5 -A SSHPorts -m set --match-set SSHPorts src -j REJECT --reject-with icmp-port-unreachable

#Test rule. Just in case.
#iptables -w 5 -A VPNPorts -s 192.168.0.0/22 -j RETURN
iptables -w 5 -A VPNPorts -j FloodBan
iptables -w 5 -A VPNPorts -m conntrack --ctstate NEW -m recent --set --name VPNRecent
iptables -w 5 -A VPNPorts -m conntrack --ctstate NEW -m recent --rcheck --seconds 120 --hitcount 10 --name VPNRecent -j SET --add-set VPNPorts src
iptables -w 5 -A VPNPorts -p tcp -m set --match-set VPNPorts src -j REJECT --reject-with tcp-reset
iptables -w 5 -A VPNPorts -m set --match-set VPNPorts src -j REJECT --reject-with icmp-port-unreachable

#Test rule. Just in case
#iptables -w 5 -A FTPPorts -s 192.168.0.0/22 -j RETURN
iptables -w 5 -A FTPPorts -j FloodBan
iptables -w 5 -A FTPPorts -m conntrack --ctstate NEW -m recent --set --name FTPRecent
iptables -w 5 -A FTPPorts -m conntrack --ctstate NEW -m recent --rcheck --seconds 120 --hitcount 5 --name FTPRecent -j SET --add-set FTPPorts src
iptables -w 5 -A FTPPorts -p tcp -m set --match-set FTPPorts src -j REJECT --reject-with tcp-reset
iptables -w 5 -A FTPPorts -m set --match-set FTPPorts src -j REJECT --reject-with icmp-port-unreachable

#Test. Just in case
#iptables -w 5 -A ProxyPorts -s 192.168.0.0/22 -j RETURN
iptables -w 5 -A ProxyPorts -j FloodBan
iptables -w 5 -A ProxyPorts -m conntrack --ctstate NEW -m recent --set --name ProxyRecent
iptables -w 5 -A ProxyPorts -m conntrack --ctstate NEW -m recent --rcheck --seconds 120 --hitcount 5 --name ProxyRecent -j SET --add-set ProxyPorts src
iptables -w 5 -A ProxyPorts -p tcp -m set --match-set ProxyPorts src -j REJECT --reject-with tcp-reset
iptables -w 5 -A ProxyPorts -m set --match-set ProxyPorts src -j REJECT --reject-with icmp-port-unreachable

#Test. Just in case
#iptables -w 5 -A HoneyPorts1 -s 192.168.0.0/22 -j RETURN
iptables -w 5 -A HoneyPorts1 -j FloodBan
iptables -w 5 -A HoneyPorts1 -m conntrack --ctstate NEW -m recent --set --name HoneyRecent1
iptables -w 5 -A HoneyPorts1 -m conntrack --ctstate NEW -m recent --rcheck --seconds 60 --hitcount 3 --name HoneyRecent1 -j SET --add-set HoneyPorts1 src
iptables -w 5 -A HoneyPorts1 -m conntrack --ctstate NEW -m recent --rcheck --seconds 1800 --hitcount 7 --name HoneyRecent1 -j SET --add-set GlobalBan src
iptables -w 5 -A HoneyPorts1 -m conntrack --ctstate NEW -m recent --rcheck --seconds 7200 --hitcount 15 --name HoneyRecent1 -j SET --add-set GlobalBan src
iptables -w 5 -A HoneyPorts1 -m set --match-set GlobalBan src -m recent --name HoneyRecent1 --remove
iptables -w 5 -A HoneyPorts1 -p tcp -m set --match-set HoneyPorts1 src -j REJECT --reject-with tcp-reset
iptables -w 5 -A HoneyPorts1 -m set --match-set HoneyPorts1 src -j REJECT --reject-with icmp-port-unreachable

#Test. Just in case
#iptables -w 5 -A HoneyPorts2 -s 192.168.0.0/22 -j RETURN
iptables -w 5 -A HoneyPorts2 -j FloodBan
iptables -w 5 -A HoneyPorts2 -m conntrack --ctstate NEW -m recent --set --name HoneyRecent2
iptables -w 5 -A HoneyPorts2 -m conntrack --ctstate NEW -m recent --rcheck --seconds 60 --hitcount 3 --name HoneyRecent2 -j SET --add-set HoneyPorts2 src
iptables -w 5 -A HoneyPorts2 -m conntrack --ctstate NEW -m recent --rcheck --seconds 1800 --hitcount 7 --name HoneyRecent2 -j SET --add-set GlobalBan src
iptables -w 5 -A HoneyPorts2 -m conntrack --ctstate NEW -m recent --rcheck --seconds 7200 --hitcount 15 --name HoneyRecent2 -j SET --add-set GlobalBan src
iptables -w 5 -A HoneyPorts2 -p tcp -m set --match-set HoneyPorts2 src -j REJECT --reject-with tcp-reset
iptables -w 5 -A HoneyPorts2 -m set --match-set HoneyPorts2 src -j REJECT --reject-with icmp-port-unreachable


for port in $RDPPorts1; do
    iptables -w 5 -I INPUT 11 $iptablesPart1 --dport $port -j RDPPorts1
    iptables -w 5 -I wanin 5 $iptablesPart1 --dport $port -j RDPPorts1
done

for port in $SSHPorts; do
    iptables -w 5 -I INPUT 11 $iptablesPart1 --dport $port -j SSHPorts
#    iptables -w 5 -I wanin 5 $iptablesPart1 --dport $port -j SSHPorts
done

for port in $VPNPorts; do
    iptables -w 5 -I INPUT 11 $iptablesPart1 --dport $port -j VPNPorts
#    iptables -w 5 -I wanin 5 $iptablesPart1 --dport $port -j VPNPorts
done

for port in $FTPPorts; do
#    iptables -w 5 -I INPUT 11 $iptablesPart1 --dport $port -j FTPPorts
    iptables -w 5 -I wanin 5 $iptablesPart1 --dport $port -j FTPPorts
done

for port in $ProxyPorts; do
#    iptables -w 5 -I INPUT 11 $iptablesPart1 --dport $port -j ProxyPorts
    iptables -w 5 -I wanin 5 $iptablesPart1 --dport $port -j ProxyPorts
done

for port in $HoneyPorts1; do
    iptables -w 5 -I INPUT 11 $iptablesPart1 --dport $port -j HoneyPorts1
#    iptables -w 5 -I wanin 5 $iptablesPart1 --dport $port -j HoneyPorts1
done

for port in $HoneyPorts2; do
    iptables -w 5 -I INPUT 11 $iptablesPart1 --dport $port -j HoneyPorts2
#    iptables -w 5 -I wanin 5 $iptablesPart1 --dport $port -j HoneyPorts2
done

ipset -exist restore < /opt/root/customFW/ipset.list
