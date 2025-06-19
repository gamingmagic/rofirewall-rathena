#!/usr/bin/env bash
# rOfirewall - NFTables DDoS Shield V2.0
# INSTALLS DEPENDENCIES, MANAGES PORTS, COUNTRY/ASN BLOCK LISTS, WHITELIST IPS, APPLIES RULES
######################################################

# 0) REQUIRE ROOT
if [[ $EUID -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  exit 1
fi

# 1) INSTALL MODE: copy script to /usr/local/bin/rofirewall and make executable
if [[ "$1" == "install" ]]; then
  target="/usr/local/bin/rofirewall"
  cp "$0" "$target"
  chmod +x "$target"
  echo "Installed command: $target"
  exit 0
fi

# 2) INSTALL DEPENDENCIES (nftables, curl, whois)
if command -v apt-get &>/dev/null; then
  apt-get update && apt-get install -y nftables curl whois
elif command -v dnf &>/dev/null; then
  dnf install -y nftables curl whois
elif command -v yum &>/dev/null; then
  yum install -y nftables curl whois
elif command -v pacman &>/dev/null; then
  pacman -Sy --noconfirm nftables curl whois
else
  echo "Package manager not detected. Please install nftables, curl, and whois manually." >&2
  exit 1
fi
# Enable and start nftables
systemctl enable nftables --now

# 3) CONFIGURATION
ZONE_DIR="/usr/local/bin"
RATE_LIMIT=5   # SYN/sec per-source
PORT_FILE="$ZONE_DIR/ports.list"
BLOCK_ZONE_FILE="$ZONE_DIR/block.zone"
ASN_ZONE_SUFFIX=".zone"
WHITELIST_FILE="$ZONE_DIR/whitelist.zone"

# Ensure default ports file exists
if [[ ! -f "$PORT_FILE" ]]; then
  cat > "$PORT_FILE" <<EOF
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
EOF
fi

# Ensure whitelist file exists
if [[ ! -f "$WHITELIST_FILE" ]]; then
  touch "$WHITELIST_FILE"
fi

# Read ports into nft-friendly set
PORTS=$(awk '{printf "%s,", \$1}' "$PORT_FILE" | sed 's/,$//')
PORTS="{${PORTS}}"

# Utility: download and add a country block list file
add-block-zone() {
  local url="$1"
  local file="$ZONE_DIR/$(basename "$url")"
  echo "[+] Fetching country list: $url -> $file"
  curl -fsSL "$url" -o "$file"
  echo "[+] Added block-zone file: $file"
}

# Utility: fetch ASN prefixes via RADB
add-block-asn() {
  local asn="$1"
  local file="$ZONE_DIR/AS${asn}${ASN_ZONE_SUFFIX}"
  echo "[+] Fetching ASN $asn prefixes -> $file"
  whois -h whois.radb.net "-i origin AS${asn}" \
    | awk '/route:/ {print \$2}' > "$file"
  echo "[+] Added ASN block list: $file"
}

# Utility: add a port to the ports file
add-port() {
  local port="$1"
  if ! [[ "$port" =~ ^[0-9]+$ ]]; then
    echo "Error: Port must be a number." >&2
    exit 1
  fi
  if grep -qx "$port" "$PORT_FILE"; then
    echo "Port $port already in whitelist." >&2
  else
    echo "$port" >> "$PORT_FILE"
    echo "[+] Added port to whitelist: $port"
  fi
}

# Utility: whitelist a single IP
whitelist-ip() {
  local ip="$1"
  if ! [[ "$ip" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
    echo "Error: Invalid IPv4 address." >&2
    exit 1
  fi
  if grep -qx "$ip" "$WHITELIST_FILE"; then
    echo "IP $ip already whitelisted." >&2
  else
    echo "$ip" >> "$WHITELIST_FILE"
    echo "[+] Whitelisted IP: $ip"
  fi
}

# 4) COMMAND-LINE MODES
case "$1" in
  install)
    # handled above
    ;;
  add-port)
    add-port "$2"; exit 0
    ;;
  add-block-zone)
    add-block-zone "$2"; exit 0
    ;;
  add-block-asn)
    add-block-asn "$2"; exit 0
    ;;
  whitelist-ip)
    whitelist-ip "$2"; exit 0
    ;;
  *)
    # full apply
    ;;
esac

# 5) FETCH default block-zone (China)
add-block-zone https://www.ipdeny.com/ipblocks/data/countries/cn.zone

# 6) FLUSH existing nftables ruleset
nft flush ruleset

# 7) DEFINE table, sets, and chains
nft <<-EOF
 table inet filter {
  set whitelist     { type ipv4_addr; flags interval; }
  set block_zone    { type ipv4_addr; flags interval; }
  set block_asn     { type ipv4_addr; flags interval; }
  set allowed_ports { type integer; flags interval; }

  chain input {
    type filter hook input priority 0; policy drop;

    # allow loopback & established
    iif "lo" accept
    ct state established,related accept

    # allow whitelisted IPs
    ip saddr @whitelist accept

    # drop blacklisted zones & ASNs
    ip saddr @block_zone drop
    ip saddr @block_asn  drop

    # allow SSH
    tcp dport 22 ct state new accept

    # allow game ports from allowed_ports set
    tcp dport @allowed_ports ct state new accept

    # SYN-flood protection
    tcp flags syn ct state new limit rate $RATE_LIMIT/second drop

    # default drop
    drop
  }

  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output  priority 0; policy accept; }
 }
EOF

# 8) POPULATE sets from files
# whitelist
while IFS= read -r ip; do
  [[ "$ip" =~ ^# || -z "$ip" ]] && continue
  nft add element inet filter whitelist { $ip }
done < "$WHITELIST_FILE"

# block_zone (all .zone except ports.list & whitelist)
for file in "$ZONE_DIR"/*.zone; do
  case "$(basename "$file")" in
    whitelist.zone|ports.list) continue;;
  esac
  while IFS= read -r ip; do
    [[ "$ip" =~ ^# || -z "$ip" ]] && continue
    # determine set: if name starts with AS -> block_asn else block_zone
    if [[ "$(basename "$file")" =~ ^AS[0-9]+ ]]; then
      nft add element inet filter block_asn { $ip }
    else
      nft add element inet filter block_zone { $ip }
    fi
  done < "$file"
done

# allowed_ports
for port in $(awk '{print $1}' "$PORT_FILE"); do
  nft add element inet filter allowed_ports { $port }
done

# 9) DONE

echo "✅ rofirewall loaded: ports ($(paste -sd, "$PORT_FILE")), blocks & whitelists applied."
