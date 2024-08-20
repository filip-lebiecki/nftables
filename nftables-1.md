grep Port /etc/ssh/sshd_config

ss -4ntpl

nc -w1 -vz 172.27.97.1 22  

nc -w1 -vz 172.27.97.1 8080  

nft list ruleset  

nft -i  

list ruleset  


vi input.nft  

flush ruleset  

table ip filter {  

  chain input {  
  
  type filter hook input priority filter; policy accept;  
    
  tcp dport 22 accept  
    
  tcp dport 22 drop  

}  

}  

nft -f input.nft  

nft list ruleset  

tcp dport 22 counter accept

nft -f input.nft

nft list ruleset

counter udp dport 1234 accept

nft -f input.nft

nft list ruleset

drop

counter drop

iif lo counter accept

nft -f input.nft

nft list ruleset

nc -w1 -vz 172.27.97.1 22

ping -O 8.8.8.8

tcpdump -ni eth0 icmp

nft list ruleset

conntrack -L

ct established,related counter accept

nft -f input.nft

ping dns.google

conntrack -L -p icmp

ct state invalid counter drop

ct state new tcp dport 22 counter accept 

nft -f input.nft

nc -w1 -vz 172.27.97.1 22

nft list ruleset

nc -w1 -vz 172.27.97.1 8080

ct state new tcp dport 8080 counter accept

nft -f input.nft

nc -w1 -vz 172.27.97.1 8080

nft list ruleset

counter cnt_ssh {
}

ct state new tcp dport 22 counter name cnt_ssh accept

ct state new tcp dport 8080 counter name cnt_ssh accept

nft -f input.nft

nc -w1 -vz 172.27.97.1 22

nc -w1 -vz 172.27.97.1 8080

nft list ruleset

ct state new tcp dport { 22, 8080 } counter name "cnt_ssh" accept

nft -f input.nft

nc -w1 -vz 172.27.97.1 22

nc -w1 -vz 172.27.97.1 8080

ct state new ip saddr 172.27.97.2 tcp dport { 22, 8080 } counter name cnt_ssh accept

nft -f input.nft

nc -w1 -vz 172.27.97.1 22

nc -w1 -vz 172.27.97.1 8080

nc -w1 -vz 172.27.97.1 22

nc -w1 -vz 172.27.97.1 8080

nft list ruleset

ct state new ip saddr { 172.27.97.2, 172.27.97.3 } tcp dport { 22, 8080 } counter name cnt_ssh accept

set allowed_ips {

  typeof ip saddr
  
  elements = { 172.27.97.2, 172.27.97.3 }

}

ct state new ip saddr @allowed_ips tcp dport { 22, 8080 } counter name cnt_ssh accept

nft -f input.nft

nft list ruleset

nft add element ip filter allowed_ips { 1.1.1.1 }

nft list ruleset

ct state new ip saddr . tcp dport @allowed_ips counter name cnt_ssh accept

typeof ip saddr . tcp dport

elements = { 172.27.97.2 . 22, 172.27.97.2 . 8080, 

             172.27.97.3 . 22, 172.27.97.3 . 8080 }

nft -f input.nft

nft list ruleset
