sudo tee /usr/local/bin/rofirewall >/dev/null <<'EOF'
#!/usr/bin/env bash
# rOfirewall - IPTables DDoS Shield V2.0 + Port Forwarding (no auto-install)

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

# 2) SKIP DEPENDENCY INSTALL

# 3) CONFIGURATION
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

  # Enable IP forwarding
  sysctl -w net.ipv4.ip_forward=1
  sed -i '/^net.ipv4.ip_forward/d' /etc/sysctl.conf
  echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

  # Add forwarding rules for each port
  for p in "${ports[@]}"; do
    iptables -t nat -A PREROUTING -p tcp --dport "$p" -j DNAT --to-destination "$target_ip":"$p"
    iptables -t nat -A POSTROUTING -p tcp -d "$target_ip" --dport "$p" -j MASQUERADE
    iptables -A FORWARD -p tcp -d "$target_ip" --dport "$p" -j ACCEPT
    echo "[+] Forwarded port $p to $target_ip"
  done

  # Save rules
  iptables-save > /etc/iptables/rules.v4

  echo "✅ Forwarding applied."
}

# 4) COMMAND-LINE MODES
case "$1" in
  install) ;;  # handled above
  add-port) add-port "$@"; exit 0;;
  add-block-zone) add-block-zone "$@"; exit 0;;
  add-block-asn) add-block-asn "$@"; exit 0;;
  whitelist-ip) whitelist-ip "$@"; exit 0;;
  forward) forward "$@"; exit 0;;
  *) ;;  # proceed
esac

# 5) FETCH default China zone
add-block-zone "$2" https://www.ipdeny.com/ipblocks/data/countries/cn.zone || true

# 6) FLUSH iptables & ipset
iptables -F
iptables -X
ipset destroy || true

# 7) CREATE IPSETS
ipset create block_zone hash:net -exist
ipset create block_asn hash:net -exist
ipset create whitelist hash:ip -exist

# Populate whitelist
while read -r ip; do [[ "$ip" =~ ^#|^$ ]] && continue; ipset add whitelist "$ip" -exist; done < "$WHITELIST_FILE"
# Populate block zones & ASNs
for file in "$ZONE_DIR"/*.zone; do
  base=$(basename "$file")
  set="block_zone"
  [[ "$base" =~ ^AS[0-9]+ ]] && set="block_asn"
  while read -r ip; do [[ "$ip" =~ ^#|^$ ]] && continue; ipset add "$set" "$ip" -exist; done < "$file"
done

# 8) BUILD iptables rules
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m set --match-set whitelist src -j ACCEPT
iptables -A INPUT -m set --match-set block_zone src -j DROP
iptables -A INPUT -m set --match-set block_asn src -j DROP
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

while read -r p; do
  iptables -A INPUT -p tcp --dport "$p" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
  iptables -A INPUT -p tcp --dport "$p" -m limit --limit "$RATE_LIMIT/sec" --limit-burst "$RATE_LIMIT" -j ACCEPT
done < "$PORT_FILE"

iptables -A INPUT -j DROP

# 9) SAVE
iptables-save > /etc/iptables/rules.v4
ipset save > /etc/iptables/ipsets.conf

echo "✅ rofirewall (iptables) loaded: ports ($(paste -sd, "$PORT_FILE")), blocks & whitelists applied."
EOF
sudo chmod +x /usr/local/bin/rofirewall
