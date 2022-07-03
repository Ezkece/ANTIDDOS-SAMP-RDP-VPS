#echo "reset iptables"
iptables -F
#echo "Block TCP-CONNECT scan attempts (SYN bit packets)"
iptables -A INPUT -p tcp --syn -i eth0 -m state --state NEW -m recent --update --seconds 1 --hitcount 1 -j DROP
#echo "Block TCP-SYN scan attempts (only SYN bit packets)"
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH SYN -i eth0 -m state --state NEW -m recent --update --seconds 1 --hitcount 1 -j DROP
#echo "Block TCP-FIN scan attempts (only FIN bit packets)"
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH FIN -i eth0 -m state --state NEW -m recent --update --seconds 1 --hitcount 1 -j DROP
#echo "Block TCP-ACK scan attempts (only ACK bit packets)"
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH ACK -i eth0 -m state --state NEW -m recent --update --seconds 1 --hitcount 1 -j DROP
#echo "Block TCP-NULL scan attempts (packets without flag)"
iptables -A INPUT -m conntrack --ctstate INVALID -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH SYN,RST,ACK,FIN,URG,PSH -j DROP
#echo "Block "Christmas Tree" TCP-XMAS scan attempts (packets with FIN, URG, PSH bits)"
iptables -A INPUT -m conntrack --ctstate NEW -p tcp --tcp-flags SYN,RST,ACK,FIN,URG,PSH FIN,URG,PSH -i eth0 -m state --state NEW -m recent --update --seconds 1 --hitcount 1 -j DROP
#echo "Block DOS - Ping of Death"
iptables -A INPUT -p ICMP --icmp-type echo-request -m length --length 60:65535 -j ACCEPT
#echo "Block DOS - Teardrop"
iptables -A INPUT -p UDP -f -j DROP
#echo "Block DDOS - Smurf"
iptables -A INPUT -j REJECT -p icmp --icmp-type echo-request
iptables -A INPUT -p icmp -j DROP --icmp-type echo-request
iptables -A OUTPUT -p icmp -j DROP --icmp-type echo-reply
#echo "Block DDOS - UDP-flood (Pepsi)"
iptables -A INPUT -p udp --dport 7777 -i eth0 -m state --state NEW -m recent --set
iptables -A INPUT -p udp --dport 7777 -i eth0 -m state --state NEW -m recent --update --seconds 1 --hitcount 1 -j DROP
iptables -t nat -A PREROUTING -p udp --dport 7777 -s 127.0.0.1 -m string --algo bm --string 'SAMP' -j REDIRECT --to-port 7777
iptables -t nat -A PREROUTING -p udp --dport 7777 -m string --algo bm --string 'SAMP' -j REDIRECT --to-port 7777
iptables -I INPUT -p udp --dport 7777 -m string --algo bm --string 'SAMP' -m hashlimit ! --hashlimit-upto 3/sec --hashlimit-burst 3/sec --hashlimit-mode srcip --hashlimit-name query -j DROP
iptables -I INPUT -p udp --dport 7777  -m  string --algo kmp   --hex-string   '|081e77da|' -m recent --name test ! --rcheck  -m recent --name test --set   -j  DROP
iptables -I INPUT -p udp --dport 7777  -m  string --algo kmp   --hex-string   '|081e77da|'  -m recent --name test --rcheck --seconds 2  --hitcount 1     -j DROP 
iptables -I INPUT  -p udp --dport 7777  -m  string --algo kmp   --hex-string   '|53414d50|' -m  string --algo kmp   --hex-string   '|611e63|'  -m recent --name limitC7777 ! --rcheck  -m recent --name limitC7777 --set -j DROP
iptables -I INPUT  -p udp --dport 7777   -m  string --algo kmp   --hex-string   '|53414d50|' -m  string --algo kmp   --hex-string   '|611e63|' -m recent --name limitC7777 --rcheck  --seconds 2 --hitcount 1   -j DROP
iptables -I INPUT  -p udp --dport 7777  -m  string --algo kmp   --hex-string   '|53414d50|' -m  string --algo kmp   --hex-string   '|611e69|'  -m recent --name limitI7777 ! --rcheck  -m recent --name limitI7777 --set 
iptables -I INPUT  -p udp --dport 7777   -m  string --algo kmp   --hex-string   '|53414d50|' -m  string --algo kmp   --hex-string   '|611e69|' -m recent --name limitI7777 --rcheck  --seconds 2 --hitcount 1   -j DROP
iptables -I INPUT  -p udp --dport 7777  -m  string --algo kmp   --hex-string   '|53414d50|' -m  string --algo kmp   --hex-string   '|611e72|'  -m recent --name limitR7777 ! --rcheck  -m recent --name limitR7777 --set -j DROP
iptables -I INPUT -p udp --dport 7777 -m string --algo kmp --hex-string '|53414d50|' -m string --algo kmp --hex-string '|611e72|' -m recent --name limitR7777 --rcheck --seconds 2 --hitcount 1 -j DROP
#echo "Block DDOS - SMBnuke"
iptables -A INPUT -p UDP --dport 135:139 -j DROP
#echo "Block DDOS - Fraggle"
iptables -A INPUT -p UDP -m pkttype --pkt-type broadcast -j DROP
iptables -A INPUT -p UDP -m limit --limit 1/s -j ACCEPT
#echo "Block DDOS - Jolt"
iptables -A INPUT -p ICMP -j DROP
#echo "port 80 sama 443"
iptables -A INPUT -p tcp --dport 80 -i eth0 -m state --state NEW -m recent --update --seconds 1 --hitcount 1 -j DROP
iptables -A INPUT -p tcp --destination-port 80 -j DROP
iptables -A INPUT -p tcp --destination-port 443 -j DROP
iptables -A INPUT -p tcp --dport 443 -i eth0 -m state --state NEW -m recent --update --seconds 1 --hitcount 1 -j DROP
#echo "layer 7 GET & POST"
iptables -I INPUT -p tcp --dport 80 -m string --string 'GET / HTTP/1.1' --algo bm -j DROP
iptables -I INPUT -p tcp --dport 443 -m string --string 'POST / HTTP/1.1' --algo bm -j DROP
iptables -I INPUT -p udp --dport 7777 -m string --string 'POST / HTTP/1.1' --algo bm -j DROP
#echo "iptables show"
iptables -L
#print
echo "ANTIDDOS JetX#7327 IS READY"