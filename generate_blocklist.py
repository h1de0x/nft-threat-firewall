#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 h1de0x
# Project: https://github.com/h1de0x/nft-threat-firewall

from __future__ import annotations

import gzip
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import yaml


PROJECT_URL = "https://github.com/h1de0x/nft-threat-firewall"
CONFIG_PATH = "sources.yml"
DIST_DIR = Path("dist")

NFT_OUTPUT_PATH = DIST_DIR / "blocklist.nft"
NFT_LOG_OUTPUT_PATH = DIST_DIR / "blocklist-log.nft"
NFT_SET_OUTPUT_PATH = DIST_DIR / "blocklist-set.nft"
TXT_OUTPUT_PATH = DIST_DIR / "blocklist.txt"
TXT_GZ_OUTPUT_PATH = DIST_DIR / "blocklist.txt.gz"
METADATA_OUTPUT_PATH = DIST_DIR / "metadata.json"

TABLE_NAME = "nft_threat_firewall"
SET_NAME = "blocked_ipv4"
PRIVATE_IPV4_RANGES = "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }"

USER_AGENT = (
    "nft-threat-firewall/1.0 "
    "(+https://github.com/h1de0x/nft-threat-firewall)"
)
REQUEST_TIMEOUT = 60

IPV4_PATTERN = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"
CIDR_RE = re.compile(rf"(?<![\d.])({IPV4_PATTERN})/(\d{{1,2}})(?![\d.])")
RANGE_RE = re.compile(rf"(?<![\d.])({IPV4_PATTERN})\s*[-–]\s*({IPV4_PATTERN})(?![\d.])")
IP_RE = re.compile(rf"(?<![\d.])({IPV4_PATTERN})(?![\d.])")

Range = tuple[int, int]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def int_to_ip(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


def is_public_ipv4(ip: ipaddress.IPv4Address) -> bool:
    return ip.is_global


def add_ip(ranges: list[Range], ip_text: str) -> None:
    try:
        ip = ipaddress.IPv4Address(ip_text)
    except ValueError:
        return

    if not is_public_ipv4(ip):
        return

    value = int(ip)
    ranges.append((value, value))


def add_range(ranges: list[Range], start_text: str, end_text: str) -> None:
    try:
        start_ip = ipaddress.IPv4Address(start_text)
        end_ip = ipaddress.IPv4Address(end_text)
    except ValueError:
        return

    if int(start_ip) > int(end_ip):
        start_ip, end_ip = end_ip, start_ip

    if not is_public_ipv4(start_ip) or not is_public_ipv4(end_ip):
        return

    ranges.append((int(start_ip), int(end_ip)))


def add_cidr(ranges: list[Range], ip_text: str, prefix_text: str) -> None:
    try:
        prefix = int(prefix_text)
        network = ipaddress.IPv4Network(f"{ip_text}/{prefix}", strict=False)
    except ValueError:
        return

    if not is_public_ipv4(network.network_address):
        return

    if not is_public_ipv4(network.broadcast_address):
        return

    ranges.append((int(network.network_address), int(network.broadcast_address)))


def strip_inline_comment(line: str) -> str:
    line = line.strip()

    if not line:
        return ""

    if line.startswith("#"):
        return ""

    if ";" in line:
        line = line.split(";", 1)[0].strip()

    line = re.split(r"\s+#", line, maxsplit=1)[0].strip()

    return line


def parse_dshield_style_line(line: str, ranges: list[Range]) -> bool:
    parts = line.split()

    if len(parts) < 2:
        return False

    if not IP_RE.fullmatch(parts[0]):
        return False

    if not parts[1].isdigit():
        return False

    prefix = int(parts[1])

    if prefix < 0 or prefix > 32:
        return False

    before = len(ranges)
    add_cidr(ranges, parts[0], parts[1])

    return len(ranges) > before


def parse_text_to_ranges(text: str, source_name: str) -> list[Range]:
    ranges: list[Range] = []

    for raw_line in text.splitlines():
        line = strip_inline_comment(raw_line)

        if not line:
            continue

        if source_name == "dshield" and parse_dshield_style_line(line, ranges):
            continue

        cidr_matches = list(CIDR_RE.finditer(line))
        if cidr_matches:
            for match in cidr_matches:
                add_cidr(ranges, match.group(1), match.group(2))
            continue

        range_matches = list(RANGE_RE.finditer(line))
        if range_matches:
            for match in range_matches:
                add_range(ranges, match.group(1), match.group(2))
            continue

        ip_matches = list(IP_RE.finditer(line))
        for match in ip_matches:
            add_ip(ranges, match.group(1))

    return ranges


def merge_ranges(ranges: list[Range]) -> list[Range]:
    if not ranges:
        return []

    sorted_ranges = sorted(ranges, key=lambda item: (item[0], item[1]))
    merged: list[Range] = []

    current_start, current_end = sorted_ranges[0]

    for start, end in sorted_ranges[1:]:
        if start <= current_end + 1:
            current_end = max(current_end, end)
        else:
            merged.append((current_start, current_end))
            current_start, current_end = start, end

    merged.append((current_start, current_end))

    return merged


def nft_element(start: int, end: int) -> str:
    if start == end:
        return int_to_ip(start)

    return f"{int_to_ip(start)}-{int_to_ip(end)}"


def download_source(name: str, url: str) -> str:
    response = requests.get(
        url,
        headers={"User-Agent": USER_AGENT},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()

    content = response.content

    if url.endswith(".gz") or content.startswith(b"\x1f\x8b"):
        try:
            content = gzip.decompress(content)
        except OSError:
            pass

    return content.decode(response.encoding or "utf-8", errors="replace")


def load_sources(path: str) -> list[dict[str, str]]:
    with Path(path).open("r", encoding="utf-8") as file:
        data: Any = yaml.safe_load(file)

    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected YAML object")

    sources = data.get("sources")

    if not isinstance(sources, list):
        raise ValueError(f"{path}: expected 'sources' list")

    result: list[dict[str, str]] = []

    for index, source in enumerate(sources, start=1):
        if not isinstance(source, dict):
            raise ValueError(f"{path}: source #{index} must be an object")

        name = source.get("name")
        url = source.get("url")

        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"{path}: source #{index} has invalid name")

        if not isinstance(url, str) or not url.strip():
            raise ValueError(f"{path}: source #{index} has invalid url")

        result.append({"name": name.strip(), "url": url.strip()})

    return result


def write_nft_elements(file, ranges: list[Range], indent: str = "            ") -> None:
    for index, (start, end) in enumerate(ranges):
        suffix = "," if index < len(ranges) - 1 else ""
        file.write(f"{indent}{nft_element(start, end)}{suffix}\n")


def write_nft_firewall(path: Path, ranges: list[Range], generated_at: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        file.write("#!/usr/sbin/nft -f\n")
        file.write(f"# Generated by: {PROJECT_URL}\n")
        file.write(f"# Generated at: {generated_at}\n")
        file.write("# Format: nftables inet table with IPv4 threat blocklist set\n")
        file.write("# Generator license: MIT\n")
        file.write("# Upstream feed data rights remain with their respective maintainers\n")
        file.write("\n")
        file.write(f"table inet {TABLE_NAME} {{\n")
        file.write(f"    set {SET_NAME} {{\n")
        file.write("        type ipv4_addr\n")
        file.write("        flags interval\n")
        file.write("        auto-merge\n")
        file.write("        elements = {\n")
        write_nft_elements(file, ranges)
        file.write("        }\n")
        file.write("    }\n")
        file.write("\n")
        file.write("    chain input {\n")
        file.write("        type filter hook input priority 0; policy accept;\n")
        file.write(f"        ip saddr != {PRIVATE_IPV4_RANGES} ip saddr @{SET_NAME} counter drop\n")
        file.write("    }\n")
        file.write("\n")
        file.write("    chain forward {\n")
        file.write("        type filter hook forward priority 0; policy accept;\n")
        file.write(f"        ip saddr != {PRIVATE_IPV4_RANGES} ip saddr @{SET_NAME} counter drop\n")
        file.write(f"        ip daddr != {PRIVATE_IPV4_RANGES} ip daddr @{SET_NAME} counter drop\n")
        file.write("    }\n")
        file.write("\n")
        file.write("    chain output {\n")
        file.write("        type filter hook output priority 0; policy accept;\n")
        file.write(f"        ip daddr != {PRIVATE_IPV4_RANGES} ip daddr @{SET_NAME} counter drop\n")
        file.write("    }\n")
        file.write("}\n")


def write_nft_firewall_with_logging(path: Path, ranges: list[Range], generated_at: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        file.write("#!/usr/sbin/nft -f\n")
        file.write(f"# Generated by: {PROJECT_URL}\n")
        file.write(f"# Generated at: {generated_at}\n")
        file.write("# Format: nftables inet table with IPv4 threat blocklist set, DROP rules, and rate-limited logs\n")
        file.write("# Generator license: MIT\n")
        file.write("# Upstream feed data rights remain with their respective maintainers\n")
        file.write("\n")
        file.write(f"table inet {TABLE_NAME} {{\n")
        file.write(f"    set {SET_NAME} {{\n")
        file.write("        type ipv4_addr\n")
        file.write("        flags interval\n")
        file.write("        auto-merge\n")
        file.write("        elements = {\n")
        write_nft_elements(file, ranges)
        file.write("        }\n")
        file.write("    }\n")
        file.write("\n")
        file.write("    chain input {\n")
        file.write("        type filter hook input priority 0; policy accept;\n")
        file.write(f"        ip saddr != {PRIVATE_IPV4_RANGES} ip saddr @{SET_NAME} limit rate 10/minute log prefix \"nft-threat IN \" flags all\n")
        file.write(f"        ip saddr != {PRIVATE_IPV4_RANGES} ip saddr @{SET_NAME} counter drop\n")
        file.write("    }\n")
        file.write("\n")
        file.write("    chain forward {\n")
        file.write("        type filter hook forward priority 0; policy accept;\n")
        file.write(f"        ip saddr != {PRIVATE_IPV4_RANGES} ip saddr @{SET_NAME} limit rate 10/minute log prefix \"nft-threat FWD-SRC \" flags all\n")
        file.write(f"        ip saddr != {PRIVATE_IPV4_RANGES} ip saddr @{SET_NAME} counter drop\n")
        file.write(f"        ip daddr != {PRIVATE_IPV4_RANGES} ip daddr @{SET_NAME} limit rate 10/minute log prefix \"nft-threat FWD-DST \" flags all\n")
        file.write(f"        ip daddr != {PRIVATE_IPV4_RANGES} ip daddr @{SET_NAME} counter drop\n")
        file.write("    }\n")
        file.write("\n")
        file.write("    chain output {\n")
        file.write("        type filter hook output priority 0; policy accept;\n")
        file.write(f"        ip daddr != {PRIVATE_IPV4_RANGES} ip daddr @{SET_NAME} limit rate 10/minute log prefix \"nft-threat OUT \" flags all\n")
        file.write(f"        ip daddr != {PRIVATE_IPV4_RANGES} ip daddr @{SET_NAME} counter drop\n")
        file.write("    }\n")
        file.write("}\n")


def write_nft_set_only(path: Path, ranges: list[Range], generated_at: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        file.write("#!/usr/sbin/nft -f\n")
        file.write(f"# Generated by: {PROJECT_URL}\n")
        file.write(f"# Generated at: {generated_at}\n")
        file.write("# Format: nftables inet table with set only, no drop rules\n")
        file.write("# Generator license: MIT\n")
        file.write("# Upstream feed data rights remain with their respective maintainers\n")
        file.write("\n")
        file.write(f"table inet {TABLE_NAME} {{\n")
        file.write(f"    set {SET_NAME} {{\n")
        file.write("        type ipv4_addr\n")
        file.write("        flags interval\n")
        file.write("        auto-merge\n")
        file.write("        elements = {\n")
        write_nft_elements(file, ranges)
        file.write("        }\n")
        file.write("    }\n")
        file.write("}\n")


def write_txt(path: Path, ranges: list[Range]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        for start, end in ranges:
            file.write(f"{int_to_ip(start)}-{int_to_ip(end)}\n")


def write_gzip_copy(source_path: Path, output_path: Path) -> None:
    with source_path.open("rb") as source_file:
        data = source_file.read()

    with gzip.open(output_path, "wb", compresslevel=9) as gzip_file:
        gzip_file.write(data)


def write_metadata(
    path: Path,
    generated_at: str,
    source_stats: list[dict[str, Any]],
    total_raw_ranges: int,
    total_merged_ranges: int,
    failed_sources: list[dict[str, str]],
) -> None:
    metadata = {
        "project": PROJECT_URL,
        "generated_at": generated_at,
        "table_name": TABLE_NAME,
        "set_name": SET_NAME,
        "total_raw_ranges": total_raw_ranges,
        "total_merged_ranges": total_merged_ranges,
        "sources": source_stats,
        "failed_sources": failed_sources,
        "outputs": {
            "nft_firewall": str(NFT_OUTPUT_PATH),
            "nft_firewall_log": str(NFT_LOG_OUTPUT_PATH),
            "nft_set_only": str(NFT_SET_OUTPUT_PATH),
            "plain_ranges": str(TXT_OUTPUT_PATH),
            "plain_ranges_gzip": str(TXT_GZ_OUTPUT_PATH),
        },
    }

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(metadata, file, ensure_ascii=False, indent=2)
        file.write("\n")


def main() -> int:
    generated_at = utc_now_iso()

    try:
        sources = load_sources(CONFIG_PATH)
    except Exception as error:
        print(f"ERROR: failed to load {CONFIG_PATH}: {error}", file=sys.stderr)
        return 1

    all_ranges: list[Range] = []
    source_stats: list[dict[str, Any]] = []
    failed_sources: list[dict[str, str]] = []

    for source in sources:
        name = source["name"]
        url = source["url"]

        print(f"Downloading {name} ...", end=" ", flush=True)

        try:
            text = download_source(name, url)
            raw_ranges = parse_text_to_ranges(text, name)
            merged_source_ranges = merge_ranges(raw_ranges)
        except Exception as error:
            print(f"FAILED: {error}")
            failed_sources.append({"name": name, "url": url, "error": str(error)})
            continue

        all_ranges.extend(raw_ranges)

        source_stats.append(
            {
                "name": name,
                "url": url,
                "raw_ranges": len(raw_ranges),
                "merged_ranges": len(merged_source_ranges),
            }
        )

        if len(raw_ranges) == 0:
            print("WARNING 0 ranges")
        else:
            print(f"parsed {len(raw_ranges)} merged {len(merged_source_ranges)}")

    global_ranges = merge_ranges(all_ranges)

    write_nft_firewall(NFT_OUTPUT_PATH, global_ranges, generated_at)
    write_nft_firewall_with_logging(NFT_LOG_OUTPUT_PATH, global_ranges, generated_at)
    write_nft_set_only(NFT_SET_OUTPUT_PATH, global_ranges, generated_at)
    write_txt(TXT_OUTPUT_PATH, global_ranges)
    write_gzip_copy(TXT_OUTPUT_PATH, TXT_GZ_OUTPUT_PATH)
    write_metadata(
        METADATA_OUTPUT_PATH,
        generated_at,
        source_stats,
        len(all_ranges),
        len(global_ranges),
        failed_sources,
    )

    print()
    print(f"Written nft firewall: {NFT_OUTPUT_PATH}")
    print(f"Written nft firewall with logs: {NFT_LOG_OUTPUT_PATH}")
    print(f"Written nft set only: {NFT_SET_OUTPUT_PATH}")
    print(f"Written plain ranges: {TXT_OUTPUT_PATH}")
    print(f"Written gzip ranges: {TXT_GZ_OUTPUT_PATH}")
    print(f"Written metadata: {METADATA_OUTPUT_PATH}")
    print(f"Raw ranges: {len(all_ranges)}")
    print(f"Global merged ranges: {len(global_ranges)}")
    print(f"Failed sources: {len(failed_sources)}")

    return 1 if failed_sources else 0


if __name__ == "__main__":
    raise SystemExit(main())
