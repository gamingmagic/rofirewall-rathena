# rOfirewall - NFTables DDoS Shield

A simple installer and manager script for nftables-based DDoS protection.

**Features:**

- Installs required dependencies: `nftables`, `curl`, `whois`
- Blocks entire countries or individual ASNs
- Whitelists only specific TCP ports (e.g. game ports + SSH)
- Whitelists individual IP addresses
- Rate-limits SYN floods
- Manages configuration via the `rofirewall` command

---

## Installation

Fetch, install dependencies, and register as a system command in one go:

```bash
sudo apt-get update \
  && sudo apt-get -y install curl \
  && cd /home \
  && curl -Lo rOfirewall.sh \
       https://raw.githubusercontent.com/gamingmagic/rofirewall-rathena/main/rofirewall.sh \
  && chmod +x rOfirewall.sh \
  && ./rOfirewall.sh install
```

(This copies `rofirewall` into `/usr/local/bin/` for global use.)

## Command Usage

All commands below assume you have `rofirewall` installed or are running `./rOfirewall.sh` from the script directory.

| Command                            | Description                                  |
|------------------------------------|----------------------------------------------|
| `rofirewall`                      | Full apply: install deps, fetch CN zone, flush and apply nftables rules, populate sets |
| `rofirewall install`             | Install the script as `/usr/local/bin/rofirewall` |
| `rofirewall add-port <PORT>`     | Add a new TCP port to the whitelist (`ports.list`) |
| `rofirewall add-block-zone <URL>`| Download and add a new country block list    |
| `rofirewall add-block-asn <ASN>` | Fetch and block all prefixes announced by the ASN |
| `rofirewall whitelist-ip <IP>`    | Add a single IPv4 address to the whitelist  |

After running any of the `add-*` commands, re-run:

```bash
sudo rofirewall
```

to rebuild and reload your nftables configuration.

---

## Configuration Files

All data files live in `/usr/local/bin` by default:

- **`ports.list`**: Whitelisted TCP ports (one per line).
- **`whitelist.zone`**: Whitelisted IPv4 addresses (one per line).
- **`*.zone`**: Country or ASN block lists (downloaded via `add-block-zone` or `add-block-asn`).

Defaults loaded on first run:

- Ports: `6900, 6121, 5121, 8888, 6964, 6164, 5164, 8884, 3306, 22`
- Country block: China (`cn.zone`)
- SYN-rate limit: `5` per second per source

To customize, edit these files or re-run appropriate `rofirewall add-*` commands.

---

## Uninstall

Remove the command and data files, and flush nftables rules:

```bash
sudo rm /usr/local/bin/rofirewall \
          /usr/local/bin/ports.list \
          /usr/local/bin/whitelist.zone \
          /usr/local/bin/*.zone
sudo nft flush ruleset
```

---

> **Warning:** This script requires **root** privileges. Always test in a non-production environment first.
