# nft-threat-firewall

Auto-updating nftables threat firewall blocklist generated from public security feeds.

`nft-threat-firewall` downloads public IPv4 threat intelligence feeds, normalizes IP addresses and ranges, globally merges them, and generates nftables-compatible blocklist files.

The project is intended for Linux servers using **nftables**.

## Features

- Downloads threat IP feeds from `sources.yml`
- Supports plain IPv4, CIDR, and IP ranges
- Filters out non-public IPv4 ranges
- Globally merges overlapping ranges
- Generates a ready-to-apply nftables firewall file
- Generates a diagnostic firewall file with rate-limited logging
- Generates a set-only nftables file for custom firewall integration
- Publishes metadata and plain text range output
- Updates automatically with GitHub Actions

## Outputs

Generated files are published in `dist/`.

| File | Description |
|---|---|
| `dist/blocklist.nft` | Full nftables table with DROP rules |
| `dist/blocklist-log.nft` | Full nftables table with DROP rules and rate-limited kernel logging |
| `dist/blocklist-set.nft` | nftables set only, no DROP rules |
| `dist/blocklist.txt` | Plain merged IPv4 ranges |
| `dist/blocklist.txt.gz` | Gzip-compressed plain ranges |
| `dist/metadata.json` | Generation metadata and source statistics |

## Raw URLs

Full nftables firewall:

```text
https://raw.githubusercontent.com/h1de0x/nft-threat-firewall/main/dist/blocklist.nft
```

Logging nftables firewall:

```text
https://raw.githubusercontent.com/h1de0x/nft-threat-firewall/main/dist/blocklist-log.nft
```

Set-only nftables file:

```text
https://raw.githubusercontent.com/h1de0x/nft-threat-firewall/main/dist/blocklist-set.nft
```

Plain ranges:

```text
https://raw.githubusercontent.com/h1de0x/nft-threat-firewall/main/dist/blocklist.txt
```

Compressed plain ranges:

```text
https://raw.githubusercontent.com/h1de0x/nft-threat-firewall/main/dist/blocklist.txt.gz
```

Metadata:

```text
https://raw.githubusercontent.com/h1de0x/nft-threat-firewall/main/dist/metadata.json
```

## nftables table

The generated nftables table is:

```nft
table inet nft_threat_firewall
```

The generated set is:

```nft
set blocked_ipv4
```

## `blocklist.nft`

`dist/blocklist.nft` is a complete nftables firewall table.

It contains:

```nft
table inet nft_threat_firewall {
    set blocked_ipv4 {
        type ipv4_addr
        flags interval
        auto-merge
        elements = {
            ...
        }
    }

    chain input {
        type filter hook input priority 0; policy accept;
        ip saddr @blocked_ipv4 counter drop
    }

    chain forward {
        type filter hook forward priority 0; policy accept;
        ip saddr @blocked_ipv4 counter drop
        ip daddr @blocked_ipv4 counter drop
    }

    chain output {
        type filter hook output priority 0; policy accept;
        ip daddr @blocked_ipv4 counter drop
    }
}
```

This blocks:

- incoming packets from listed IPs
- outgoing packets to listed IPs
- forwarded traffic from or to listed IPs

## `blocklist-log.nft`

`dist/blocklist-log.nft` is a diagnostic version of the full firewall file.

It contains the same nftables set and DROP rules as `dist/blocklist.nft`, but also adds rate-limited kernel logging before each DROP rule.

Use this version when you want to see which blocked IPs are hitting your server.

Example logging rule:

```nft
ip saddr @blocked_ipv4 limit rate 10/minute log prefix "nft-threat IN " flags all
ip saddr @blocked_ipv4 counter drop
```

The DROP rule is separate and comes after the logging rule, so packets are still dropped even when logging is rate-limited.

Download:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/h1de0x/nft-threat-firewall/main/dist/blocklist-log.nft \
  -o /tmp/blocklist-log.nft
```

Validate:

```bash
sudo nft -c -f /tmp/blocklist-log.nft
```

Apply:

```bash
sudo nft delete table inet nft_threat_firewall 2>/dev/null || true
sudo nft -f /tmp/blocklist-log.nft
```

View recent logs:

```bash
sudo journalctl -k --since "10 minutes ago" | grep nft-threat
```

Follow logs live:

```bash
sudo journalctl -kf | grep --line-buffered nft-threat
```

### Log analysis

The log prefixes have different meanings:

| Prefix | Meaning | Blocked address field |
|---|---|---|
| `nft-threat IN` | Incoming packets from blocked IPs | `SRC` |
| `nft-threat FWD-SRC` | Forwarded packets from blocked IPs | `SRC` |
| `nft-threat FWD-DST` | Forwarded packets to blocked IPs | `DST` |
| `nft-threat OUT` | Outgoing packets to blocked IPs | `DST` |

Do not mix all `SRC=` values from all `nft-threat` logs together. For `OUT` and `FWD-DST`, the blocked IP is in `DST`, not `SRC`.

Show top blocked incoming source IPs:

```bash
sudo journalctl -k --since "1 hour ago" \
  | grep 'nft-threat IN ' \
  | sed -n 's/.*SRC=\([0-9.]*\).*/\1/p' \
  | sort \
  | uniq -c \
  | sort -nr \
  | head -20
```

Show top blocked incoming source IPs with destination ports:

```bash
sudo journalctl -k --since "1 hour ago" \
  | grep 'nft-threat IN ' \
  | sed -n 's/.*SRC=\([0-9.]*\).*DPT=\([0-9]*\).*/\1 \2/p' \
  | sort \
  | uniq -c \
  | sort -nr \
  | head -30
```

Show top destination ports for blocked incoming packets:

```bash
sudo journalctl -k --since "1 hour ago" \
  | grep 'nft-threat IN ' \
  | grep -o 'DPT=[0-9]*' \
  | sort \
  | uniq -c \
  | sort -nr \
  | head -20
```

Show top blocked forwarded source IPs:

```bash
sudo journalctl -k --since "1 hour ago" \
  | grep 'nft-threat FWD-SRC ' \
  | sed -n 's/.*SRC=\([0-9.]*\).*/\1/p' \
  | sort \
  | uniq -c \
  | sort -nr \
  | head -20
```

Show top blocked forwarded destination IPs:

```bash
sudo journalctl -k --since "1 hour ago" \
  | grep 'nft-threat FWD-DST ' \
  | sed -n 's/.*DST=\([0-9.]*\).*/\1/p' \
  | sort \
  | uniq -c \
  | sort -nr \
  | head -20
```

Show top blocked outgoing destination IPs:

```bash
sudo journalctl -k --since "1 hour ago" \
  | grep 'nft-threat OUT ' \
  | sed -n 's/.*DST=\([0-9.]*\).*/\1/p' \
  | sort \
  | uniq -c \
  | sort -nr \
  | head -20
```

Check logs for a specific IP:

```bash
sudo journalctl -k --since "1 hour ago" \
  | grep nft-threat \
  | grep '95.221.202.168'
```

Show only new events from the current moment:

```bash
SINCE="$(date '+%Y-%m-%d %H:%M:%S')"
echo "$SINCE"

sudo journalctl -k --since "$SINCE" | grep nft-threat
```

### Counters

The logging rules are rate-limited, so logs do not show every dropped packet.

For total packet and byte counters, use:

```bash
sudo nft list table inet nft_threat_firewall
```

Reset counters:

```bash
sudo nft reset counters table inet nft_threat_firewall
```

Show rule handles:

```bash
sudo nft -a list table inet nft_threat_firewall
```

Use `dist/blocklist.nft` for normal quiet operation and `dist/blocklist-log.nft` for diagnostics.


### Log analysis helper script

This repository also includes a small helper script for analyzing logs produced by `dist/blocklist-log.nft`.

Copy it to the server or run it from a cloned checkout:

```bash
sudo scripts/analyze-logs.sh
```

Default time range is `24 hours ago`.

Custom time ranges:

```bash
sudo scripts/analyze-logs.sh "1 hour ago"
sudo scripts/analyze-logs.sh "10 minutes ago"
sudo scripts/analyze-logs.sh "2026-05-27 17:00:00"
```

The script prints:

- top blocked hosts;
- top blocked direction/IP/port combinations;
- top blocked `/24` networks.

Output format for direction/IP/port:

```text
COUNT DIRECTION IP PORT
```

Example:

```text
6 FWD-SRC 188.241.177.228 46580
3 IN 95.221.202.168 32600
1 IN 91.92.42.88 22
```

Direction meanings:

| Direction | Meaning |
|---|---|
| `IN` | blocked incoming traffic to the host |
| `FWD-SRC` | blocked forwarded traffic from a blocked source IP |
| `FWD-DST` | blocked forwarded traffic to a blocked destination IP |
| `OUT` | blocked outgoing traffic to a blocked destination IP |

For `IN` and `FWD-SRC`, the blocked IP is taken from `SRC`.

For `OUT` and `FWD-DST`, the blocked IP is taken from `DST`.

Forwarded traffic is common when the server runs Docker, WireGuard, VPNs, NAT, or port forwarding.


## `blocklist-set.nft`

`dist/blocklist-set.nft` contains only the nftables set.

It does not block anything by itself.

Use this file if you want to integrate the generated set into your own nftables rules manually.

## Warning

Be careful when applying this on a remote server.

If your current SSH IP is included in the generated blocklist, you may lock yourself out.

Before applying on a remote machine, make sure you have:

- VPS provider console access
- rescue console access
- another recovery method
- a tested rollback command

For safer integration, prefer `blocklist-set.nft` and attach the set to your own firewall rules.

## Validate before applying

Download the full firewall file:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/h1de0x/nft-threat-firewall/main/dist/blocklist.nft \
  -o /tmp/blocklist.nft
```

Validate syntax without applying:

```bash
sudo nft -c -f /tmp/blocklist.nft
```

If the command exits without errors, the file is syntactically valid.

## Apply full firewall

Apply the full generated firewall table:

```bash
sudo nft delete table inet nft_threat_firewall 2>/dev/null || true
sudo nft -f /tmp/blocklist.nft
```

Check loaded table:

```bash
sudo nft list table inet nft_threat_firewall
```

Check counters and rule handles:

```bash
sudo nft -a list table inet nft_threat_firewall
```

Remove the generated firewall table:

```bash
sudo nft delete table inet nft_threat_firewall
```

## Safer set-only usage

Download the set-only file:

```bash
curl -fsSL \
  https://raw.githubusercontent.com/h1de0x/nft-threat-firewall/main/dist/blocklist-set.nft \
  -o /tmp/blocklist-set.nft
```

Validate:

```bash
sudo nft -c -f /tmp/blocklist-set.nft
```

Apply:

```bash
sudo nft delete table inet nft_threat_firewall 2>/dev/null || true
sudo nft -f /tmp/blocklist-set.nft
```

After that, add your own rules in the same table.

Example:

```nft
table inet nft_threat_firewall {
    chain input {
        type filter hook input priority 0; policy accept;

        ct state established,related accept
        ip saddr @blocked_ipv4 counter drop
    }

    chain output {
        type filter hook output priority 0; policy accept;

        ct state established,related accept
        ip daddr @blocked_ipv4 counter drop
    }
}
```

Validate your custom rules before applying them:

```bash
sudo nft -c -f your-rules.nft
```

## Automatic update script

Example update script with atomic table replacement:

```bash
sudo tee /usr/local/sbin/update-nft-threat-firewall >/dev/null <<'SCRIPT'
#!/bin/sh
set -eu

URL="https://raw.githubusercontent.com/h1de0x/nft-threat-firewall/main/dist/blocklist.nft"
TABLE_NAME="nft_threat_firewall"

TMP_FILE="$(mktemp)"
BATCH_FILE="$(mktemp)"

cleanup() {
    rm -f "$TMP_FILE" "$BATCH_FILE"
}
trap cleanup EXIT

curl -fsSL "$URL" -o "$TMP_FILE"

# Use batch mode to atomically replace the table
# This prevents race conditions where packets slip through during table reload
if nft list table inet "$TABLE_NAME" >/dev/null 2>&1; then
    cat > "$BATCH_FILE" <<EOF
delete table inet $TABLE_NAME
include "$TMP_FILE"
EOF
else
    cat > "$BATCH_FILE" <<EOF
include "$TMP_FILE"
EOF
fi

# Validate syntax before applying
nft -c -f "$BATCH_FILE"

# Apply atomically
nft -f "$BATCH_FILE"
SCRIPT
```

Make it executable:

```bash
sudo chmod +x /usr/local/sbin/update-nft-threat-firewall
```

Run manually:

```bash
sudo /usr/local/sbin/update-nft-threat-firewall
```

To use the logging firewall instead, change the URL in the script to:

```text
https://raw.githubusercontent.com/h1de0x/nft-threat-firewall/main/dist/blocklist-log.nft
```

### Why batch mode?

Previous non-atomic approaches had a race condition: when deleting and recreating the table in separate commands, packets arriving between the delete and create operations could be mishandled. The batch mode (`include` directive) ensures the delete and create operations are atomic within the kernel, preventing any dropped packets during updates.

## Cron example

Update every 12 hours:

```bash
sudo crontab -e
```

Add:

```cron
17 */12 * * * /usr/local/sbin/update-nft-threat-firewall
```

## systemd timer example

Create service:

```bash
sudo tee /etc/systemd/system/nft-threat-firewall.service >/dev/null <<'EOF_SERVICE'
[Unit]
Description=Update nft-threat-firewall blocklist
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/update-nft-threat-firewall
EOF_SERVICE
```

Create timer:

```bash
sudo tee /etc/systemd/system/nft-threat-firewall.timer >/dev/null <<'EOF_TIMER'
[Unit]
Description=Run nft-threat-firewall update twice daily

[Timer]
OnCalendar=*-*-* 03,15:17:00
Persistent=true

[Install]
WantedBy=timers.target
EOF_TIMER
```

Enable timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nft-threat-firewall.timer
```

Check timer:

```bash
systemctl list-timers nft-threat-firewall.timer
```

Run update manually:

```bash
sudo systemctl start nft-threat-firewall.service
```

View logs:

```bash
journalctl -u nft-threat-firewall.service -n 100 --no-pager
```

## Local generation

Clone the repository:

```bash
git clone https://github.com/h1de0x/nft-threat-firewall.git
cd nft-threat-firewall
```

Create virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Generate blocklist:

```bash
python generate_blocklist.py
```

Validate generated nftables files:

```bash
sudo nft -c -f dist/blocklist.nft
sudo nft -c -f dist/blocklist-log.nft
sudo nft -c -f dist/blocklist-set.nft
```

## Sources

Sources are configured in:

```text
sources.yml
```

Current source categories include:

- public threat intelligence feeds
- compromised host lists
- scanner lists
- brute-force attacker lists
- malicious IP reputation feeds

The generator does not claim that every listed IP is always malicious. False positives are possible.

## Metadata

`dist/metadata.json` contains generation details:

```json
{
  "project": "https://github.com/h1de0x/nft-threat-firewall",
  "generated_at": "...",
  "table_name": "nft_threat_firewall",
  "set_name": "blocked_ipv4",
  "total_raw_ranges": 0,
  "total_merged_ranges": 0,
  "sources": [],
  "failed_sources": [],
  "outputs": {}
}
```

This file can be used for monitoring, debugging, or checking whether source feeds are still producing data.

## GitHub Actions

The blocklist is generated automatically by GitHub Actions.

The workflow:

- installs Python dependencies
- downloads all configured feeds
- generates nftables output files
- validates nftables syntax
- commits updated files into `dist/`

The workflow also supports manual runs from the GitHub Actions page.

## Limitations

- IPv4 only
- No allowlist support yet
- No per-ASN filtering yet
- No IPv6 output yet
- Feed quality depends on upstream maintainers
- False positives are possible
- This should not be treated as a complete security solution

## Recommended usage

For simple servers:

```bash
sudo nft delete table inet nft_threat_firewall 2>/dev/null || true
sudo nft -f /tmp/blocklist.nft
```

For diagnostics:

```bash
sudo nft delete table inet nft_threat_firewall 2>/dev/null || true
sudo nft -f /tmp/blocklist-log.nft
```

For production servers:

- validate before applying
- use console access for recovery
- prefer set-only integration
- keep your main firewall rules separate
- monitor counters
- test before adding automatic updates

## License

The generator code, workflow files, and documentation are licensed under the MIT License.

See [`LICENSE`](LICENSE).

Generated blocklist files are compiled from third-party public threat intelligence feeds. Rights, licenses, and usage restrictions for upstream feed data remain with their respective maintainers.

Use this project at your own risk.
