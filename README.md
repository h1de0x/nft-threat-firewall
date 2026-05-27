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
- Generates a set-only nftables file for custom firewall integration
- Publishes metadata and plain text range output
- Updates automatically with GitHub Actions

## Outputs

Generated files are published in `dist/`.

| File | Description |
|---|---|
| `dist/blocklist.nft` | Full nftables table with DROP rules |
| `dist/blocklist-set.nft` | nftables set only, no DROP rules |
| `dist/blocklist.txt` | Plain merged IPv4 ranges |
| `dist/blocklist.txt.gz` | Gzip-compressed plain ranges |
| `dist/metadata.json` | Generation metadata and source statistics |

## Raw URLs

Full nftables firewall:

```text
https://raw.githubusercontent.com/h1de0x/nft-threat-firewall/main/dist/blocklist.nft
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

Check counters:

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

Example update script:

```bash
sudo tee /usr/local/sbin/update-nft-threat-firewall >/dev/null <<'SCRIPT'
#!/bin/sh
set -eu

URL="https://raw.githubusercontent.com/h1de0x/nft-threat-firewall/main/dist/blocklist.nft"
TMP_FILE="$(mktemp)"

cleanup() {
    rm -f "$TMP_FILE"
}

trap cleanup EXIT

curl -fsSL "$URL" -o "$TMP_FILE"

nft -c -f "$TMP_FILE"

nft delete table inet nft_threat_firewall 2>/dev/null || true
nft -f "$TMP_FILE"
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
