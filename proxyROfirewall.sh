#How to use:
#sudo rofirewall start or sudo rofirewall restart — apply everything!
#sudo rofirewall clear-all — remove all rules.
#sudo rofirewall forward <IP> <PORTS> — add forwarding rule(s) on top of this config.
#sudo tee /usr/local/bin/rofirewall >/dev/null <<'EOF'

#!/usr/bin/env bash
# rOfirewall - DDoS + NAT + Custom Filters + Country Allow + Forward + Start/Restart + HTTP Block + Clear

# 0) REQUIRE ROOT
if [[ $EUID -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  exit 1
fi

# 1) INSTALL MODE
if [[ "$1" == "install" ]]; then
  target="/usr/local/bin/rofirewall"
  cp "$0" "$target"
  chmod +x "$target"
  echo "Installed command: $target"
  exit 0
fi

# 2) CONFIGURATION
ZONE_DIR="/usr/local/bin"
RATE_LIMIT=5
PORT_FILE="$ZONE_DIR/ports.list"
WHITELIST_FILE="$ZONE_DIR/whitelist.zone"
ASN_ZONE_SUFFIX=".zone"

# Default ports list
if [[ ! -f "$PORT_FILE" ]]; then
  cat > "$PORT_FILE" <<EOI
6900
6121
5121
8888
6964
6164
5164
8884
3306
22
EOI
fi
if [[ ! -f "$WHITELIST_FILE" ]]; then
  touch "$WHITELIST_FILE"
fi

# UTILITIES
add-port() {
  [[ -z "$2" ]] && echo "Usage: rofirewall add-port <PORT>" && exit 1
  local port="$2"
  if ! grep -qx "$port" "$PORT_FILE"; then
    echo "$port" >> "$PORT_FILE"
    echo "[+] Added port: $port"
  else
    echo "Port $port already exists."
  fi
}
add-block-zone() {
  [[ -z "$2" ]] && echo "Usage: rofirewall add-block-zone <URL>" && exit 1
  local url="$2" file="$ZONE_DIR/$(basename "$url")"
  curl -fsSL "$url" -o "$file"
  echo "[+] Added zone: $file"
}
add-block-asn() {
  [[ -z "$2" ]] && echo "Usage: rofirewall add-block-asn <ASN>" && exit 1
  local asn="$2" file="$ZONE_DIR/AS${asn}${ASN_ZONE_SUFFIX}"
  whois -h whois.radb.net "-i origin AS${asn}" | awk '/route:/ {print $2}' > "$file"
  echo "[+] Added ASN zone: $file"
}
whitelist-ip() {
  [[ -z "$2" ]] && echo "Usage: rofirewall whitelist-ip <IP>" && exit 1
  local ip="$2"
  if ! grep -qx "$ip" "$WHITELIST_FILE"; then
    echo "$ip" >> "$WHITELIST_FILE"
    echo "[+] Whitelisted IP: $ip"
  else
    echo "IP $ip already whitelisted."
  fi
}
forward() {
  if [[ -z "$2" || -z "$3" ]]; then
    echo "Usage: rofirewall forward <IP> <PORT1> [PORT2] [PORT3] [...]"
    exit 1
  fi
  local target_ip="$2"
  shift 2
  local ports=( "$@" )
  sysctl -w net.ipv4.ip_forward=1
  sed -i '/^net.ipv4.ip_forward/d' /etc/sysctl.conf
  echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
  for p in "${ports[@]}"; do
    iptables -t nat -A PREROUTING -p tcp --dport "$p" -j DNAT --to-destination "$target_ip":"$p"
    iptables -t nat -A POSTROUTING -p tcp -d "$target_ip" --dport "$p" -j MASQUERADE
    iptables -A FORWARD -p tcp -d "$target_ip" --dport "$p" -j ACCEPT
    echo "[+] Forwarded port $p to $target_ip"
  done
  iptables-save > /etc/iptables/rules.v4
  echo "✅ Forwarding applied."
}
clear-all() {
  iptables -F
  iptables -X
  iptables -t nat -F
  iptables -t nat -X
  iptables -t mangle -F
  iptables -t mangle -X
  iptables -t raw -F
  iptables -t raw -X
  iptables -t security -F
  iptables -t security -X
  iptables -P INPUT ACCEPT
  iptables -P FORWARD ACCEPT
  iptables -P OUTPUT ACCEPT
  ipset destroy || true
  echo "✅ Cleared all iptables rules and reset policies."
}

# 4) COMMAND-LINE MODES
case "$1" in
  install) ;;
  add-port) add-port "$@"; exit 0;;
  add-block-zone) add-block-zone "$@"; exit 0;;
  add-block-asn) add-block-asn "$@"; exit 0;;
  whitelist-ip) whitelist-ip "$@"; exit 0;;
  forward) forward "$@"; exit 0;;
  clear-all) clear-all; exit 0;;
  start|restart|"") ;; # run default rules for start, restart, or no argument
  *) ;;      # proceed as default (start)
esac

### 1) CLEAN SLATE
iptables -F
iptables -t nat -F
iptables -X
iptables -t nat -X

### 2) DEFAULT POLICIES
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT

### 3) HOST INPUT RULES
iptables -A INPUT -i lo  -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Always allow SSH & your app port (22/3000)
iptables -A INPUT -p tcp --dport 22   -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 3000 -m conntrack --ctstate NEW -j ACCEPT

### 4) FORWARD ESTABLISHED
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

### 5) ENABLE NAT
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -j MASQUERADE

### 6) CLUSTER A (15.235.159.76)
iptables -t nat -A PREROUTING -p tcp --dport 6964 -j DNAT --to-destination 15.235.159.76:6964
iptables -t nat -A PREROUTING -p tcp --dport 6164 -j DNAT --to-destination 15.235.159.76:6164
iptables -t nat -A PREROUTING -p tcp --dport 5164 -j DNAT --to-destination 15.235.159.76:5164

# Knock→allow for A
iptables -A FORWARD -p tcp --dport 6964  -m conntrack --ctstate NEW -m recent --name RS_A --set   -j ACCEPT
iptables -A FORWARD -p tcp --dport 6164  -m conntrack --ctstate NEW -m recent --name RS_A --rcheck --seconds 300 -j ACCEPT
iptables -A FORWARD -p tcp --dport 5164  -m conntrack --ctstate NEW -m recent --name RS_A --rcheck --seconds 300 -j ACCEPT
iptables -A FORWARD -p tcp --dport 6164 -j DROP
iptables -A FORWARD -p tcp --dport 5164 -j DROP

### 7) SKZYONE U32 FILTERS
iptables -A INPUT -p tcp -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12&0xFFFFFF00=0x50000000 && 0>>22&0x3C@12>>8&0xFF=0" -j DROP
iptables -A INPUT -p tcp -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12&0xFFFFFF00=0x80000000 && 0>>22&0x3C@12>>8&0xFF=0" -j DROP
iptables -A INPUT -p tcp -m u32 --u32 "6&0xFF=0x6 && 0>>22&0x3C@12&0xFFFFFF00=0x70000000 && 0>>22&0x3C@12>>8&0xFF=0" -j DROP

# COUNTRY ALLOW SYSTEM
COUNTRIES=(sg ph id th)
ipset create allow_countries hash:net -exist
for c in "${COUNTRIES[@]}"; do
  zonefile="$ZONE_DIR/$c.zone"
  curl -fsSL "https://www.ipdeny.com/ipblocks/data/countries/$c.zone" -o "$zonefile"
  while read -r ip; do
    [[ "$ip" =~ ^#|^$ ]] && continue
    ipset add allow_countries "$ip" -exist
  done < "$zonefile"
done

ipset create block_zone hash:net -exist
ipset create block_asn hash:net -exist
ipset create whitelist hash:ip -exist

while read -r ip; do [[ "$ip" =~ ^#|^$ ]] && continue; ipset add whitelist "$ip" -exist; done < "$WHITELIST_FILE"
for file in "$ZONE_DIR"/*.zone; do
  base=$(basename "$file")
  set="block_zone"
  [[ "$base" =~ ^AS[0-9]+ ]] && set="block_asn"
  [[ "$base" =~ ^(sg|ph|id|th)\.zone$ ]] && continue
  while read -r ip; do [[ "$ip" =~ ^#|^$ ]] && continue; ipset add "$set" "$ip" -exist; done < "$file"
done

# Allow from whitelist & allowed countries
iptables -A INPUT -m set --match-set whitelist src -j ACCEPT
iptables -A INPUT -m set --match-set allow_countries src -j ACCEPT
iptables -A INPUT -m set --match-set block_zone src -j DROP
iptables -A INPUT -m set --match-set block_asn src -j DROP

# Your game/app ports with ratelimit
while read -r p; do
  iptables -A INPUT -p tcp --dport "$p" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
  iptables -A INPUT -p tcp --dport "$p" -m limit --limit "$RATE_LIMIT/sec" --limit-burst "$RATE_LIMIT" -j ACCEPT
done < "$PORT_FILE"

# BLOCK ALL HTTP METHODS & PACKETS
iptables -A INPUT -p tcp -m string --string "GET " --algo bm -j DROP
iptables -A INPUT -p tcp -m string --string "POST " --algo bm -j DROP
iptables -A INPUT -p tcp -m string --string "HEAD " --algo bm -j DROP
iptables -A INPUT -p tcp -m string --string "HTTP" --algo bm -j DROP

iptables -A INPUT -j DROP

iptables-save > /etc/iptables/rules.v4
ipset save > /etc/iptables/ipsets.conf

echo "✅ rofirewall: custom/NAT/knock/country/HTTP/u32/whitelist/ratelimit rules applied."
iptables -t nat -L PREROUTING -n --line-numbers
iptables -L FORWARD     -n --line-numbers
EOF
sudo chmod +x /usr/local/bin/rofirewall
